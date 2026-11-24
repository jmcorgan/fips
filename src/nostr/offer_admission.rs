//! Per-npub admission control for inbound traversal offers, shared by the
//! signal task and the offers it spawns.
//!
//! The counts and the decisions are the machine's
//! (`machine::traversal::admission`); this wraps them in one
//! `std::sync::Mutex`, held for one call and never across an `.await`, and
//! hands out an [`OfferPermit`] that gives its slot back when it is dropped,
//! so the spawned handling of an offer releases its slot however it ends.

use std::sync::{Arc, Mutex};

pub(super) use super::machine::traversal::admission::AdmissionReject;
use super::machine::traversal::admission::{Admission, SlotId};

/// A granted admission. Its slot is given back on drop, so the caller only
/// has to keep this alive for as long as the offer is being processed.
pub(super) struct OfferPermit {
    admission: Arc<Mutex<Admission>>,
    slot: SlotId,
}

impl Drop for OfferPermit {
    fn drop(&mut self) {
        lock(&self.admission).release(self.slot);
    }
}

/// The admission, under its lock.
fn lock(admission: &Mutex<Admission>) -> std::sync::MutexGuard<'_, Admission> {
    admission.lock().expect("offer-admission mutex poisoned")
}

/// Admits inbound offers against a per-sender allowance nested inside a
/// global bound.
pub(super) struct OfferAdmission {
    admission: Arc<Mutex<Admission>>,
}

impl OfferAdmission {
    /// Build an admission gate bounded globally by `global_limit` and per
    /// sender npub by `per_sender_limit`.
    pub(super) fn new(global_limit: usize, per_sender_limit: usize) -> Self {
        Self {
            admission: Arc::new(Mutex::new(Admission::new(
                global_limit,
                per_sender_limit,
                fips_core::utils::hash::KeyedHasher::new::<crate::identity::OsEntropy>(),
            ))),
        }
    }

    /// Try to take one slot for `npub`, or say which bound refused it.
    pub(super) fn try_admit(&self, npub: &str) -> Result<OfferPermit, AdmissionReject> {
        let slot = lock(&self.admission).try_admit(npub)?;
        Ok(OfferPermit {
            admission: Arc::clone(&self.admission),
            slot,
        })
    }

    /// How many sender npubs the map currently holds.
    #[cfg(test)]
    pub(super) fn tracked_senders(&self) -> usize {
        lock(&self.admission).tracked_senders()
    }
}

#[cfg(test)]
#[path = "tests/offer_admission.rs"]
mod tests;
