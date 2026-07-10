//! Synchronous decision core for the Nostr overlay-advert lifecycle.
//!
//! `AdvertMachine` owns the advert-related state that previously lived
//! directly on `NostrRendezvous` — the peer advert cache, the local
//! advert we publish, and the id of our most recently published advert
//! event — and hosts the *decision* logic for publishing, caching,
//! fetching, and pruning adverts.
//!
//! Following the sans-IO shape used by `failure_state`, every method here
//! is synchronous, performs no network I/O and no `.await`, holds its
//! state behind `std::sync::Mutex`, and takes the current time as an
//! explicit `now_ms: u64` input rather than reading a clock. The async
//! driver on `NostrRendezvous` reads the clock at the call site, invokes
//! these methods, and performs the actual relay I/O (`send_event_to`,
//! `fetch_events_from`, gift-wrap crypto), event signing, NIP-09 deletes,
//! and `Notify` wakeups described by the returned decisions.

use std::collections::HashMap;
use std::sync::Mutex;

use nostr::prelude::{Event, EventId};

use super::runtime::{NostrRendezvous, endpoint_advert_is_publicly_usable};
use super::types::{
    ADVERT_IDENTIFIER, ADVERT_VERSION, BootstrapError, CachedOverlayAdvert, OverlayAdvert,
    OverlayEndpointAdvert,
};

/// What the async driver should do to satisfy a publish request. Returned
/// by [`AdvertMachine::plan_publish`]; the machine performs the pure
/// decision (which advert body, or a delete, or nothing) and the driver
/// executes the corresponding relay I/O.
#[derive(Debug, Clone)]
pub(super) enum PublishPlan {
    /// Nothing to publish (advertising disabled with no prior event, no
    /// local advert yet, or the advert has no publicly usable endpoints).
    Nothing,
    /// Advertising is disabled but a prior advert event exists; the driver
    /// should emit a NIP-09 delete for `EventId` then call
    /// [`AdvertMachine::clear_event_id`].
    Delete(EventId),
    /// Publish this fully-prepared advert body. The driver builds the
    /// tags/expiration, signs, sends, then records the new event id via
    /// [`AdvertMachine::set_event_id`].
    Publish(OverlayAdvert),
}

pub(super) struct AdvertMachine {
    /// Our own npub. Used to avoid logging/attributing self-authored
    /// adverts as peer discoveries.
    npub: String,
    /// Whether this node advertises at all (`config.advertise`).
    advertise: bool,
    /// Grace-extended max age for a cached advert, in ms
    /// (`advert_ttl_secs * 1000 * stale-grace-multiplier`).
    advert_max_age_ms: u64,
    /// Size cap for the peer advert cache.
    cache_max_entries: usize,
    /// Peer advert cache keyed by author npub.
    cache: Mutex<HashMap<String, CachedOverlayAdvert>>,
    /// The advert body we currently want to publish, if any.
    local_advert: Mutex<Option<OverlayAdvert>>,
    /// Id of our most recently published advert event (for NIP-09 delete
    /// on withdrawal).
    current_event_id: Mutex<Option<EventId>>,
}

impl AdvertMachine {
    pub(super) fn new(
        npub: String,
        advertise: bool,
        advert_max_age_ms: u64,
        cache_max_entries: usize,
    ) -> Self {
        Self {
            npub,
            advertise,
            advert_max_age_ms,
            cache_max_entries,
            cache: Mutex::new(HashMap::new()),
            local_advert: Mutex::new(None),
            current_event_id: Mutex::new(None),
        }
    }

    // --- validity (time-injected) --------------------------------------

    /// Compute the validity horizon of an advert event, or `None` if it is
    /// already stale. Thin time-injected wrapper over the pure
    /// `compute_advert_valid_until_ms`.
    pub(super) fn event_valid_until_ms(&self, event: &Event, now_ms: u64) -> Option<u64> {
        NostrRendezvous::compute_advert_valid_until_ms(event, self.advert_max_age_ms, now_ms)
    }

    // --- cache: prune / observe / fetch --------------------------------

    /// TTL + size-cap eviction. Drops entries past their validity horizon,
    /// then evicts the oldest (by `valid_until_ms`) beyond the cap.
    ///
    /// Returns `Some((evicted, retained))` when a size-cap eviction
    /// occurred so the driver can log it; `None` otherwise.
    pub(super) fn prune(&self, now_ms: u64) -> Option<(usize, usize)> {
        let mut cache = self.lock_cache();
        cache.retain(|_, entry| entry.valid_until_ms > now_ms);
        if cache.len() <= self.cache_max_entries {
            return None;
        }

        let mut oldest = cache
            .iter()
            .map(|(npub, entry)| (npub.clone(), entry.valid_until_ms))
            .collect::<Vec<_>>();
        oldest.sort_by_key(|(_, ts)| *ts);
        let overflow = cache.len().saturating_sub(self.cache_max_entries);
        for (npub, _) in oldest.into_iter().take(overflow) {
            cache.remove(&npub);
        }
        Some((overflow, cache.len()))
    }

    /// Observe an advert event received on the notify loop. Replaces the
    /// cached entry iff its `created_at` is newer-or-equal to the cached
    /// one (or none is cached).
    ///
    /// Returns `true` when the caller should log a "peer cached" line —
    /// i.e. the entry was (re)cached *and* it is not our own advert.
    pub(super) fn observe_advert(
        &self,
        author_npub: &str,
        advert: OverlayAdvert,
        created_at: u64,
        valid_until_ms: u64,
    ) -> bool {
        let mut cache = self.lock_cache();
        let should_replace = cache
            .get(author_npub)
            .map(|existing| existing.created_at <= created_at)
            .unwrap_or(true);
        if !should_replace {
            return false;
        }
        let is_peer = author_npub != self.npub;
        cache.insert(
            author_npub.to_string(),
            CachedOverlayAdvert {
                author_npub: author_npub.to_string(),
                advert,
                created_at,
                valid_until_ms,
            },
        );
        is_peer
    }

    /// Cache-hit lookup for the fetch path: return the cached advert body
    /// if present, `None` if the driver must fetch from relays.
    pub(super) fn cached_advert(&self, peer_npub: &str) -> Option<OverlayAdvert> {
        self.lock_cache()
            .get(peer_npub)
            .map(|cached| cached.advert.clone())
    }

    /// The `created_at` of a cached advert, if any. Used by the stale-check
    /// refetch path to decide whether a relay result is newer.
    pub(super) fn cached_created_at(&self, peer_npub: &str) -> Option<u64> {
        self.lock_cache()
            .get(peer_npub)
            .map(|cached| cached.created_at)
    }

    /// Insert a freshly-fetched advert into the cache (fetch-miss path and
    /// stale-check refresh).
    pub(super) fn insert_fetched(&self, peer_npub: &str, cached: CachedOverlayAdvert) {
        self.lock_cache().insert(peer_npub.to_string(), cached);
    }

    /// Remove a peer's cached advert (stale-check eviction).
    pub(super) fn remove(&self, peer_npub: &str) {
        self.lock_cache().remove(peer_npub);
    }

    /// Validity-filtered snapshot of cacheable peers for open discovery:
    /// entries authored by someone other than us and still valid at
    /// `now_ms`.
    pub(super) fn open_discovery_candidates(
        &self,
        max: usize,
        now_ms: u64,
    ) -> Vec<(String, Vec<OverlayEndpointAdvert>, u64)> {
        let cache = self.lock_cache();
        cache
            .values()
            .filter(|entry| entry.author_npub != self.npub)
            .filter(|entry| entry.valid_until_ms > now_ms)
            .map(|entry| {
                (
                    entry.author_npub.clone(),
                    entry.advert.endpoints.clone(),
                    entry.created_at,
                )
            })
            .take(max)
            .collect()
    }

    // --- local advert / publish ----------------------------------------

    /// Set the local advert we want to publish. Returns `true` when the
    /// value changed (so the driver should request a republish).
    pub(super) fn set_local_advert(&self, advert: Option<OverlayAdvert>) -> bool {
        let mut slot = self.lock_local();
        if *slot == advert {
            false
        } else {
            *slot = advert;
            true
        }
    }

    /// Build the publish decision: which advert body to publish, a delete
    /// to emit, or nothing. Pure logic — the driver performs the relay I/O
    /// and event signing.
    pub(super) fn plan_publish(&self) -> Result<PublishPlan, BootstrapError> {
        let previous_event_id = *self.lock_event_id();
        if !self.advertise {
            return Ok(match previous_event_id {
                Some(event_id) => PublishPlan::Delete(event_id),
                None => PublishPlan::Nothing,
            });
        }

        let mut advert = match self.lock_local().clone() {
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

        if advert.has_udp_nat_endpoint() {
            if advert
                .signal_relays
                .as_ref()
                .is_none_or(|relays| relays.is_empty())
            {
                return Err(BootstrapError::InvalidAdvert(
                    "udp:nat endpoint requires non-empty signalRelays".to_string(),
                ));
            }
            if advert
                .stun_servers
                .as_ref()
                .is_none_or(|servers| servers.is_empty())
            {
                return Err(BootstrapError::InvalidAdvert(
                    "udp:nat endpoint requires non-empty stunServers".to_string(),
                ));
            }
        } else {
            advert.signal_relays = None;
            advert.stun_servers = None;
        }

        Ok(PublishPlan::Publish(advert))
    }

    // --- current advert event id (NIP-09 delete-on-withdraw) -----------

    /// Record the id of a just-published advert event.
    pub(super) fn set_event_id(&self, event_id: EventId) {
        *self.lock_event_id() = Some(event_id);
    }

    /// Clear the recorded advert event id (after emitting a delete).
    pub(super) fn clear_event_id(&self) {
        *self.lock_event_id() = None;
    }

    /// Take and clear the recorded advert event id (shutdown path).
    pub(super) fn take_event_id(&self) -> Option<EventId> {
        self.lock_event_id().take()
    }

    // --- lock helpers ---------------------------------------------------

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, HashMap<String, CachedOverlayAdvert>> {
        self.cache
            .lock()
            .expect("advert-machine cache mutex poisoned")
    }

    fn lock_local(&self) -> std::sync::MutexGuard<'_, Option<OverlayAdvert>> {
        self.local_advert
            .lock()
            .expect("advert-machine local-advert mutex poisoned")
    }

    fn lock_event_id(&self) -> std::sync::MutexGuard<'_, Option<EventId>> {
        self.current_event_id
            .lock()
            .expect("advert-machine event-id mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::types::OverlayTransportKind;

    fn ep(addr: &str) -> OverlayEndpointAdvert {
        OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: addr.to_string(),
        }
    }

    fn advert(endpoints: Vec<OverlayEndpointAdvert>) -> OverlayAdvert {
        OverlayAdvert {
            identifier: ADVERT_IDENTIFIER.to_string(),
            version: ADVERT_VERSION,
            endpoints,
            signal_relays: None,
            stun_servers: None,
        }
    }

    fn cached(author: &str, created_at: u64, valid_until_ms: u64) -> CachedOverlayAdvert {
        CachedOverlayAdvert {
            author_npub: author.to_string(),
            advert: advert(vec![ep("1.2.3.4:9000")]),
            created_at,
            valid_until_ms,
        }
    }

    fn machine() -> AdvertMachine {
        // npub=self, advertise=true, max-age huge, cap=3
        AdvertMachine::new("npub1self".to_string(), true, 10_000_000, 3)
    }

    #[test]
    fn observe_advert_replaces_only_when_newer_and_flags_peer() {
        let m = machine();
        // Fresh peer advert -> cached, log flagged (peer).
        assert!(m.observe_advert("npub1peer", advert(vec![ep("1.2.3.4:9000")]), 100, 5000));
        // Older created_at -> not replaced, no log.
        assert!(!m.observe_advert("npub1peer", advert(vec![ep("1.2.3.4:9001")]), 50, 5000));
        assert_eq!(m.cached_created_at("npub1peer"), Some(100));
        // Newer created_at -> replaced, log flagged.
        assert!(m.observe_advert("npub1peer", advert(vec![ep("1.2.3.4:9002")]), 200, 5000));
        assert_eq!(m.cached_created_at("npub1peer"), Some(200));
    }

    #[test]
    fn observe_advert_self_author_caches_but_does_not_flag_log() {
        let m = machine();
        // Own advert is still cached (should_replace true) but must NOT be
        // flagged as a peer-cached log line.
        assert!(!m.observe_advert("npub1self", advert(vec![ep("1.2.3.4:9000")]), 100, 5000));
        assert_eq!(m.cached_created_at("npub1self"), Some(100));
    }

    #[test]
    fn prune_drops_expired_and_reports_no_eviction_under_cap() {
        let m = machine();
        m.insert_fetched("npub1a", cached("npub1a", 1, 1000));
        m.insert_fetched("npub1b", cached("npub1b", 1, 3000));
        // now=2000 -> npub1a expired, npub1b retained, under cap -> None.
        assert_eq!(m.prune(2000), None);
        assert_eq!(m.cached_created_at("npub1a"), None);
        assert!(m.cached_created_at("npub1b").is_some());
    }

    #[test]
    fn prune_size_cap_evicts_oldest_by_valid_until() {
        let m = machine(); // cap = 3
        // Four still-valid entries; oldest valid_until must be evicted.
        m.insert_fetched("npub1a", cached("npub1a", 1, 1000));
        m.insert_fetched("npub1b", cached("npub1b", 1, 2000));
        m.insert_fetched("npub1c", cached("npub1c", 1, 3000));
        m.insert_fetched("npub1d", cached("npub1d", 1, 4000));
        let evicted = m.prune(500);
        assert_eq!(evicted, Some((1, 3)));
        // Oldest validity (npub1a) evicted; newest kept.
        assert_eq!(m.cached_created_at("npub1a"), None);
        assert!(m.cached_created_at("npub1d").is_some());
    }

    #[test]
    fn open_discovery_candidates_filters_self_and_expired() {
        let m = machine();
        m.insert_fetched("npub1self", cached("npub1self", 1, 9000));
        m.insert_fetched("npub1peer", cached("npub1peer", 1, 9000));
        m.insert_fetched("npub1stale", cached("npub1stale", 1, 1000));
        let out = m.open_discovery_candidates(10, 2000);
        assert_eq!(out.len(), 1, "only the valid non-self peer survives");
        assert_eq!(out[0].0, "npub1peer");
    }

    #[test]
    fn open_discovery_candidates_respects_max() {
        let m = machine();
        for i in 0..5 {
            let npub = format!("npub1p{i}");
            m.insert_fetched(&npub, cached(&npub, 1, 9000));
        }
        assert_eq!(m.open_discovery_candidates(2, 1000).len(), 2);
    }

    #[test]
    fn set_local_advert_detects_change() {
        let m = machine();
        let a = advert(vec![ep("1.2.3.4:9000")]);
        assert!(m.set_local_advert(Some(a.clone())), "first set is a change");
        assert!(
            !m.set_local_advert(Some(a.clone())),
            "identical set is no change"
        );
        assert!(m.set_local_advert(None), "clearing is a change");
    }

    #[test]
    fn plan_publish_strips_relays_for_non_nat_advert() {
        let m = machine();
        let mut a = advert(vec![ep("1.2.3.4:9000")]);
        a.signal_relays = Some(vec!["wss://relay".to_string()]);
        a.stun_servers = Some(vec!["stun:host:3478".to_string()]);
        m.set_local_advert(Some(a));
        match m.plan_publish().expect("plan ok") {
            PublishPlan::Publish(out) => {
                assert!(
                    out.signal_relays.is_none(),
                    "non-nat advert strips signalRelays"
                );
                assert!(
                    out.stun_servers.is_none(),
                    "non-nat advert strips stunServers"
                );
                assert_eq!(out.identifier, ADVERT_IDENTIFIER);
                assert_eq!(out.version, ADVERT_VERSION);
            }
            other => panic!("expected Publish, got {other:?}"),
        }
    }

    #[test]
    fn plan_publish_keeps_relays_for_nat_advert() {
        let m = machine();
        let mut a = advert(vec![ep("nat")]);
        a.signal_relays = Some(vec!["wss://relay".to_string()]);
        a.stun_servers = Some(vec!["stun:host:3478".to_string()]);
        m.set_local_advert(Some(a));
        match m.plan_publish().expect("plan ok") {
            PublishPlan::Publish(out) => {
                assert!(out.has_udp_nat_endpoint());
                assert_eq!(out.signal_relays.as_deref().map(<[_]>::len), Some(1));
                assert_eq!(out.stun_servers.as_deref().map(<[_]>::len), Some(1));
            }
            other => panic!("expected Publish, got {other:?}"),
        }
    }

    #[test]
    fn plan_publish_nat_without_relays_errors() {
        let m = machine();
        m.set_local_advert(Some(advert(vec![ep("nat")])));
        assert!(matches!(
            m.plan_publish(),
            Err(BootstrapError::InvalidAdvert(_))
        ));
    }

    #[test]
    fn plan_publish_nothing_when_no_local_advert() {
        let m = machine();
        assert!(matches!(m.plan_publish(), Ok(PublishPlan::Nothing)));
    }

    #[test]
    fn plan_publish_nothing_when_disabled_without_prior_event() {
        // advertise=false, no prior event id -> Nothing.
        let m = AdvertMachine::new("npub1self".to_string(), false, 10_000_000, 3);
        m.set_local_advert(Some(advert(vec![ep("1.2.3.4:9000")])));
        assert!(matches!(m.plan_publish(), Ok(PublishPlan::Nothing)));
    }

    #[test]
    fn event_id_set_clear_take_roundtrip() {
        let m = machine();
        assert_eq!(m.take_event_id(), None);
        m.clear_event_id();
        assert_eq!(m.take_event_id(), None);
    }
}
