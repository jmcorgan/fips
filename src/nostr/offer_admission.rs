//! Per-npub admission control for inbound traversal offers.
//!
//! The intake path used to hold a single global semaphore sized by
//! `max_concurrent_incoming_offers`, acquired before any identity check, so
//! one sender could hold every slot and deny traversal onboarding to every
//! other peer. This type takes a per-npub permit and a global permit
//! together, so a single npub can occupy at most its own allowance.
//!
//! **What this does not fix.** The global pool stays exhaustible. Nostr
//! identities are free to generate and the signal subscription carries no
//! author restriction, so an attacker willing to run
//! `ceil(global_limit / per_sender_limit)` throwaway npubs still saturates
//! the pool at an unchanged total offer rate, and an honest peer still gets
//! the same drop. What the per-npub allowance buys is that one identity can
//! no longer do it alone, and that the refusal a spamming sender receives is
//! distinguishable in the log from genuine saturation. A defence that raises
//! the attacker's cost in more than keypairs would have to price the offer
//! itself, which is a larger change than this one.
//!
//! **Lock discipline, which the correctness of the map bound rests on.**
//! `try_admit` does the prune, the map lookup and both permit acquisitions
//! under one `std::sync::Mutex` and never awaits inside it. The prune uses
//! `Arc::strong_count` as an exact idle test: an `OwnedSemaphorePermit` owns
//! an `Arc<Semaphore>`, so a count of 1 means the map holds the only
//! reference and no permit for that npub is outstanding. Moving
//! `try_acquire_owned` outside the lock breaks this — a concurrent prune
//! could evict an entry whose permit was still live, and the next offer from
//! that npub would build a fresh semaphore and over-admit. No test in this
//! module catches that rearrangement, so it has to be preserved by reading.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Why an inbound offer was refused a slot.
///
/// The two classes stay apart because they are different operator stories:
/// one says the node is saturated, the other says a single sender is over its
/// allowance and everyone else is unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AdmissionReject {
    /// The sender already holds its whole per-npub allowance.
    SenderFull,
    /// The node is at `max_concurrent_incoming_offers` across all senders.
    GlobalFull,
}

/// A granted admission. Both permits release on drop, so the caller only has
/// to keep this alive for as long as the offer is being processed.
pub(super) struct OfferPermit {
    _sender: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

/// Admits inbound offers against a per-sender allowance nested inside a
/// global bound.
pub(super) struct OfferAdmission {
    global: Arc<Semaphore>,
    per_sender: Mutex<HashMap<String, Arc<Semaphore>>>,
    per_sender_limit: usize,
}

impl OfferAdmission {
    /// Build an admission gate bounded globally by `global_limit` and per
    /// sender npub by `per_sender_limit`.
    pub(super) fn new(global_limit: usize, per_sender_limit: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global_limit)),
            per_sender: Mutex::new(HashMap::new()),
            per_sender_limit,
        }
    }

    /// Try to take one slot for `npub`, or say which bound refused it.
    ///
    /// The per-sender check runs first so a spamming sender is turned away
    /// without ever touching the global pool, and therefore causes no churn
    /// there.
    pub(super) fn try_admit(&self, npub: &str) -> Result<OfferPermit, AdmissionReject> {
        let mut map = self
            .per_sender
            .lock()
            .expect("offer-admission mutex poisoned");

        // Drop entries with no outstanding permit. Every live per-sender
        // permit implies a live global permit, so at most `global_limit`
        // senders survive a prune and the map is bounded by
        // `global_limit + 1` after the insert below. A benign race with a
        // permit dropping concurrently can only retain an idle entry for one
        // more round, or drop an entry all of whose permits are already free;
        // neither over-admits.
        map.retain(|_, sem| Arc::strong_count(sem) > 1);

        let sem = map
            .entry(npub.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.per_sender_limit)))
            .clone();
        let sender = sem
            .try_acquire_owned()
            .map_err(|_| AdmissionReject::SenderFull)?;
        let global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmissionReject::GlobalFull)?;

        Ok(OfferPermit {
            _sender: sender,
            _global: global,
        })
    }

    /// How many sender npubs the map currently holds.
    #[cfg(test)]
    pub(super) fn tracked_senders(&self) -> usize {
        self.per_sender
            .lock()
            .expect("offer-admission mutex poisoned")
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_sender_cannot_take_more_than_its_allowance_or_deny_another_sender() {
        let admission = OfferAdmission::new(16, 4);

        // The attacker pushes for the whole global pool, which is what makes
        // the victim's assertion below discriminating: without per-npub
        // accounting it takes all sixteen and the victim is refused.
        let mut held = Vec::new();
        let mut refusals = Vec::new();
        for _ in 0..16 {
            match admission.try_admit("npub1attacker") {
                Ok(permit) => held.push(permit),
                Err(reject) => refusals.push(reject),
            }
        }

        assert_eq!(
            held.len(),
            4,
            "one npub must not hold more than its own allowance"
        );
        assert!(
            refusals
                .iter()
                .all(|reject| *reject == AdmissionReject::SenderFull),
            "a sender over its allowance is refused on its own account, not on the pool's: {refusals:?}"
        );
        assert!(
            admission.try_admit("npub1victim").is_ok(),
            "a second sender must still be admitted while the pool has slots"
        );
    }

    #[test]
    fn several_peers_bootstrapping_at_once_are_all_admitted() {
        let admission = OfferAdmission::new(16, 4);

        let mut held = Vec::new();
        for peer in 0..8 {
            held.push(
                admission
                    .try_admit(&format!("npub1peer{peer}"))
                    .unwrap_or_else(|e| panic!("peer {peer} should be admitted, got {e:?}")),
            );
        }
    }

    #[test]
    fn an_idle_sender_is_reclaimed_so_the_map_cannot_grow_without_bound() {
        let admission = OfferAdmission::new(16, 4);

        // Three senders stay busy for the whole test, so the map bound and
        // not a collapse to a single entry is what the assertion measures.
        let mut held = Vec::new();
        for peer in 0..3 {
            held.push(
                admission
                    .try_admit(&format!("npub1busy{peer}"))
                    .expect("a busy peer is inside both bounds"),
            );
        }

        for sender in 0..100 {
            drop(
                admission
                    .try_admit(&format!("npub1transient{sender}"))
                    .expect("a transient sender is inside both bounds"),
            );
        }

        // Three still-held entries, plus the last transient sender, which was
        // inserted after the prune that would have removed it.
        assert_eq!(admission.tracked_senders(), 4);
    }
}
