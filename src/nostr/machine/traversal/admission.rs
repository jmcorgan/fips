//! Per-npub admission of inbound traversal offers, as counts.
//!
//! An offer takes one slot of its sender's allowance and one of the node's
//! global bound, and gives both back when its handling ends. The two are
//! counted here rather than held as semaphore permits: an admitted offer is
//! a [`SlotId`], and [`Admission::release`] ends it. A sender's entry goes
//! when its count reaches zero, so the table holds only senders with an
//! offer in hand, at most the global bound of them.
//!
//! **What this does not fix.** The global bound stays exhaustible. Nostr
//! identities are free to generate and the signal subscription carries no
//! author restriction, so an attacker willing to run
//! `ceil(global_limit / per_sender_limit)` throwaway npubs still fills it at
//! an unchanged total offer rate, and an honest peer still gets the same
//! drop. What the per-npub allowance buys is that one identity can no longer
//! do it alone, and that the refusal a spamming sender receives is
//! distinguishable in the log from genuine saturation.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use fips_core::utils::hash::{HashMap, KeyedHasher};

/// Why an inbound offer was refused a slot.
///
/// The two classes stay apart because they are different operator stories:
/// one says the node is saturated, the other says a single sender is over its
/// allowance and everyone else is unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionReject {
    /// The sender already holds its whole per-npub allowance.
    SenderFull,
    /// The node is at `max_concurrent_incoming_offers` across all senders.
    GlobalFull,
}

/// One admitted offer, held until its handling ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotId(u64);

/// Admits inbound offers against a per-sender allowance nested inside a
/// global bound.
#[derive(Debug)]
pub struct Admission {
    global_limit: usize,
    per_sender_limit: usize,
    /// The offers in hand from each sender, for senders with any. Keyed by
    /// the sender's npub, which a peer chooses.
    per_sender: HashMap<String, usize>,
    /// The sender of each slot in hand.
    slots: BTreeMap<SlotId, String>,
    next_slot: u64,
}

impl Admission {
    /// An admission bounded globally by `global_limit` and per sender npub by
    /// `per_sender_limit`, with its sender table keyed by `hasher`.
    pub fn new(global_limit: usize, per_sender_limit: usize, hasher: KeyedHasher) -> Self {
        Self {
            global_limit,
            per_sender_limit,
            per_sender: HashMap::with_hasher(hasher),
            slots: BTreeMap::new(),
            next_slot: 0,
        }
    }

    /// Take one slot for `npub`, or say which bound refused it.
    ///
    /// The per-sender check runs first so a spamming sender is turned away
    /// without ever touching the global bound.
    pub fn try_admit(&mut self, npub: &str) -> Result<SlotId, AdmissionReject> {
        let held = self.per_sender.get(npub).copied().unwrap_or(0);
        if held >= self.per_sender_limit {
            return Err(AdmissionReject::SenderFull);
        }
        if self.slots.len() >= self.global_limit {
            return Err(AdmissionReject::GlobalFull);
        }
        *self.per_sender.entry(npub.to_string()).or_insert(0) += 1;
        let slot = SlotId(self.next_slot);
        self.next_slot += 1;
        self.slots.insert(slot, npub.to_string());
        Ok(slot)
    }

    /// Give `slot` back. A sender whose last slot this was is forgotten.
    pub fn release(&mut self, slot: SlotId) {
        let Some(npub) = self.slots.remove(&slot) else {
            return;
        };
        if let Some(held) = self.per_sender.get_mut(&npub) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                self.per_sender.remove(&npub);
            }
        }
    }

    /// How many senders have an offer in hand.
    #[cfg(test)]
    pub fn tracked_senders(&self) -> usize {
        self.per_sender.len()
    }
}

#[cfg(test)]
#[path = "tests/admission.rs"]
mod tests;
