//! The local advert and the decision to publish it. The runtime builds the
//! advert from its transports, signs the Nostr event and sends it; this
//! decides which body, if any, goes out. No NIP-09 deletion is ever sent for
//! an advert: a stopped advert is left to NIP-40 expiration.

use alloc::string::ToString;

use super::super::error::Error;
use super::super::types::{ADVERT_IDENTIFIER, ADVERT_VERSION, OverlayAdvert};
use super::{NatGap, apply_nat_rule, endpoint_advert_is_publicly_usable};

/// What the async driver should do to satisfy a publish request. Returned
/// by [`Publisher::plan_publish`]; the machine performs the pure
/// decision (which advert body, or nothing) and the driver executes the
/// corresponding relay I/O.
#[derive(Debug, Clone)]
pub enum PublishPlan {
    /// Nothing to publish (advertising disabled, no local advert yet, or
    /// the advert has no publicly usable endpoints).
    Nothing,
    /// Publish this fully-prepared advert body. The driver builds the
    /// tags/expiration, signs, and sends.
    Publish(OverlayAdvert),
}

/// The advert this node wants to publish, and whether it advertises at all.
#[derive(Debug)]
pub struct Publisher {
    /// Whether this node advertises at all (`config.advertise`).
    advertise: bool,
    /// The advert body we currently want to publish, if any.
    local_advert: Option<OverlayAdvert>,
}

impl Publisher {
    /// A publisher with no local advert yet.
    pub fn new(advertise: bool) -> Self {
        Self {
            advertise,
            local_advert: None,
        }
    }

    /// Set the local advert we want to publish. Returns `true` when the
    /// value changed (so the driver should request a republish).
    pub fn set_local_advert(&mut self, advert: Option<OverlayAdvert>) -> bool {
        if self.local_advert == advert {
            false
        } else {
            self.local_advert = advert;
            true
        }
    }

    /// Build the publish decision: which advert body to publish, or nothing.
    /// Pure logic — the driver performs the relay I/O and event signing.
    pub fn plan_publish(&self) -> Result<PublishPlan, Error> {
        if !self.advertise {
            return Ok(PublishPlan::Nothing);
        }

        let mut advert = match self.local_advert.clone() {
            Some(advert) => advert,
            // Transient absence (e.g., a single tick during startup where
            // build_overlay_advert briefly returns None). Don't proactively
            // emit a NIP-09 delete: the next publish supersedes the old
            // event via parameterized-replaceable semantics, and the NIP-40
            // expiration tag bounds the worst case if we never re-publish.
            None => return Ok(PublishPlan::Nothing),
        };

        advert.identifier = ADVERT_IDENTIFIER.to_string();
        advert.version = ADVERT_VERSION;
        advert.endpoints.retain(endpoint_advert_is_publicly_usable);
        // Defensive: build_overlay_advert returns None on empty endpoints,
        // so this is only reachable from non-lifecycle callers.
        if advert.endpoints.is_empty() {
            return Ok(PublishPlan::Nothing);
        }

        match apply_nat_rule(&mut advert) {
            Ok(()) => Ok(PublishPlan::Publish(advert)),
            Err(NatGap::SignalRelays) => Err(Error::InvalidAdvert(
                "udp:nat endpoint requires non-empty signalRelays".to_string(),
            )),
            Err(NatGap::StunServers) => Err(Error::InvalidAdvert(
                "udp:nat endpoint requires non-empty stunServers".to_string(),
            )),
        }
    }
}

#[cfg(test)]
#[path = "tests/publisher.rs"]
mod tests;
