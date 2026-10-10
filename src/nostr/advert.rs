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

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nostr::prelude::{Event, EventId};
use rand::seq::IteratorRandom;

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

/// How long the advert cache must stay below its cap before the cache-full
/// warning is re-armed. An advert flood that pushes the cache across its cap
/// once per advert then produces at most two lines a minute: the warning when
/// the cap is first reached and the release line once the hold has passed.
const BOUND_LOG_HOLD: Duration = Duration::from_secs(60);

/// What the cache did with one advert offered to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AdvertAdmission {
    /// The author was already cached and this advert replaced its entry.
    Updated,
    /// The author was not cached and now is.
    Admitted,
    /// The author was already cached with a newer advert; nothing changed.
    Stale,
    /// The cache is full and the author is neither configured nor linked, so
    /// the advert was not cached. `first_at_bound` is set on the first such
    /// refusal after the cache was last below its cap for `BOUND_LOG_HOLD`,
    /// so the caller can log the bound once.
    Refused { first_at_bound: bool },
}

/// What one prune of the advert cache removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct PruneReport {
    /// Entries dropped because their validity horizon had passed.
    pub(super) expired: usize,
    /// Unprotected entries removed to bring the cache back to its cap.
    pub(super) evicted: usize,
    /// Entries left in the cache.
    pub(super) retained: usize,
}

/// One cached advert and the order in which its author was admitted.
struct CacheEntry {
    cached: CachedOverlayAdvert,
    /// Taken from `AdvertCache::next_seq` when the author was admitted and
    /// kept across replacements of the same author's advert.
    admitted_seq: u64,
}

/// The peer advert cache keyed by author npub, with the admission counter
/// that orders its entries.
#[derive(Default)]
struct AdvertCache {
    entries: HashMap<String, CacheEntry>,
    next_seq: u64,
}

impl AdvertCache {
    /// Drop every entry whose validity horizon is not after `now_ms`, and
    /// return how many went.
    fn drop_expired(&mut self, now_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| entry.cached.valid_until_ms > now_ms);
        before - self.entries.len()
    }

    /// The unprotected entry admitted most recently, if any.
    ///
    /// This is the entry that makes room for a protected author. Choosing
    /// the newest rather than the soonest-expiring entry matters under
    /// attack: honest adverts carry earlier horizons than freshly minted
    /// ones, so a soonest-horizon rule would let someone who links key after
    /// key (an inbound dial or a traversal offer is enough) and publishes
    /// each one's advert evict one honest incumbent per key, without limit.
    /// Under this rule each such key evicts only the previous one.
    fn newest_unprotected(&self, protected: &HashSet<String>) -> Option<String> {
        self.entries
            .iter()
            .filter(|(npub, _)| !protected.contains(*npub))
            .max_by_key(|(_, entry)| entry.admitted_seq)
            .map(|(npub, _)| npub.clone())
    }

    fn insert_new(&mut self, npub: &str, cached: CachedOverlayAdvert) {
        let admitted_seq = self.next_seq;
        self.next_seq += 1;
        self.entries.insert(
            npub.to_string(),
            CacheEntry {
                cached,
                admitted_seq,
            },
        );
    }
}

/// The cache-full log latch: set when the cache first refuses an advert,
/// cleared once the cache has stayed below its cap for `BOUND_LOG_HOLD`.
#[derive(Default)]
struct BoundLatch {
    latched: bool,
    /// Refusals since the latch was set, the first included.
    refused: u64,
    /// When the cache was first seen below its cap while latched.
    below_since: Option<Instant>,
}

pub(super) struct AdvertMachine {
    /// Our own npub. Used to keep self-authored adverts out of open
    /// discovery.
    npub: String,
    /// Whether this node advertises at all (`config.advertise`).
    advertise: bool,
    /// Grace-extended max age for a cached advert, in ms
    /// (`advert_ttl_secs * 1000 * stale-grace-multiplier`).
    advert_max_age_ms: u64,
    /// Size cap for the peer advert cache.
    cache_max_entries: usize,
    /// Authors whose adverts the cache keeps when it is full: the configured
    /// peers and the authors with a currently established link, as the node
    /// last pushed them.
    ///
    /// Lock order for the three cache mutexes: `protected`, then `cache`,
    /// then `latch`. A method that needs more than one takes them in that
    /// order and never takes an earlier one while holding a later one.
    protected: Mutex<HashSet<String>>,
    /// Peer advert cache keyed by author npub.
    cache: Mutex<AdvertCache>,
    /// The cache-full log latch.
    latch: Mutex<BoundLatch>,
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
            protected: Mutex::new(HashSet::new()),
            cache: Mutex::new(AdvertCache::default()),
            latch: Mutex::new(BoundLatch::default()),
            local_advert: Mutex::new(None),
            current_event_id: Mutex::new(None),
        }
    }

    /// Replace the set of authors whose adverts the cache protects.
    pub(super) fn set_protected(&self, npubs: HashSet<String>) {
        *self.lock_protected() = npubs;
    }

    /// The set of protected authors, for tests that check what the node
    /// pushed.
    #[cfg(test)]
    pub(super) fn protected(&self) -> HashSet<String> {
        self.lock_protected().clone()
    }

    // --- validity (time-injected) --------------------------------------

    /// Compute the validity horizon of an advert event, or `None` if it is
    /// already stale. Thin time-injected wrapper over the pure
    /// `compute_advert_valid_until_ms`.
    pub(super) fn event_valid_until_ms(&self, event: &Event, now_ms: u64) -> Option<u64> {
        NostrRendezvous::compute_advert_valid_until_ms(event, self.advert_max_age_ms, now_ms)
    }

    // --- cache: prune / observe / fetch --------------------------------

    /// TTL and size-cap maintenance. Drops entries past their validity
    /// horizon; then, while the cache is above its cap, removes unprotected
    /// entries, the most recently admitted first. Protected entries are never
    /// removed before they expire, so the cache can stay above its cap by
    /// protected entries alone.
    pub(super) fn prune(&self, now_ms: u64) -> PruneReport {
        let protected = self.lock_protected();
        let mut cache = self.lock_cache();
        let expired = cache.drop_expired(now_ms);
        let mut evicted = 0;
        while cache.entries.len() > self.cache_max_entries {
            let Some(victim) = cache.newest_unprotected(&protected) else {
                break;
            };
            cache.entries.remove(&victim);
            evicted += 1;
        }
        PruneReport {
            expired,
            evicted,
            retained: cache.entries.len(),
        }
    }

    /// Offer an advert event received on the notify loop to the cache.
    ///
    /// An author already cached has its entry replaced when this advert's
    /// `created_at` is not older than the cached one. A new author is
    /// admitted while the cache has room. When the cache is full, expired
    /// entries are dropped first; then a protected author (a configured peer,
    /// or one with an established link) is still admitted, taking the slot of
    /// the unprotected entry admitted most recently, and anyone else is
    /// refused rather than evicting an entry.
    pub(super) fn observe_advert(
        &self,
        author_npub: &str,
        advert: OverlayAdvert,
        created_at: u64,
        valid_until_ms: u64,
        now_ms: u64,
    ) -> AdvertAdmission {
        self.admit(
            author_npub,
            CachedOverlayAdvert {
                author_npub: author_npub.to_string(),
                advert,
                created_at,
                valid_until_ms,
            },
            now_ms,
        )
    }

    /// Cache-hit lookup for the fetch path: return the cached advert body
    /// if present, `None` if the driver must fetch from relays.
    pub(super) fn cached_advert(&self, peer_npub: &str) -> Option<OverlayAdvert> {
        self.lock_cache()
            .entries
            .get(peer_npub)
            .map(|entry| entry.cached.advert.clone())
    }

    /// The `created_at` of a cached advert, if any. Used by the stale-check
    /// refetch path to decide whether a relay result is newer.
    pub(super) fn cached_created_at(&self, peer_npub: &str) -> Option<u64> {
        self.lock_cache()
            .entries
            .get(peer_npub)
            .map(|entry| entry.cached.created_at)
    }

    /// Offer a freshly fetched advert to the cache (fetch-miss path and
    /// stale-check refresh), under the same rule as [`Self::observe_advert`]:
    /// a configured or linked author is always cached, anyone else only
    /// while the cache has room.
    pub(super) fn insert_fetched(
        &self,
        peer_npub: &str,
        cached: CachedOverlayAdvert,
        now_ms: u64,
    ) -> AdvertAdmission {
        self.admit(peer_npub, cached, now_ms)
    }

    /// Remove a peer's cached advert (stale-check eviction).
    pub(super) fn remove(&self, peer_npub: &str) {
        self.lock_cache().entries.remove(peer_npub);
    }

    /// The admission rule shared by the notify loop and the fetch paths.
    fn admit(&self, npub: &str, cached: CachedOverlayAdvert, now_ms: u64) -> AdvertAdmission {
        let protected = self.lock_protected();
        let mut cache = self.lock_cache();
        if let Some(existing) = cache.entries.get_mut(npub) {
            if existing.cached.created_at > cached.created_at {
                return AdvertAdmission::Stale;
            }
            existing.cached = cached;
            return AdvertAdmission::Updated;
        }
        if cache.entries.len() >= self.cache_max_entries {
            cache.drop_expired(now_ms);
        }
        if protected.contains(npub) {
            if cache.entries.len() >= self.cache_max_entries
                && let Some(victim) = cache.newest_unprotected(&protected)
            {
                cache.entries.remove(&victim);
            }
            cache.insert_new(npub, cached);
            return AdvertAdmission::Admitted;
        }
        if cache.entries.len() < self.cache_max_entries {
            cache.insert_new(npub, cached);
            return AdvertAdmission::Admitted;
        }
        let mut latch = self.lock_latch();
        latch.below_since = None;
        latch.refused = latch.refused.saturating_add(1);
        let first_at_bound = !latch.latched;
        latch.latched = true;
        AdvertAdmission::Refused { first_at_bound }
    }

    /// Release the cache-full latch once the cache has stayed below its cap
    /// for `BOUND_LOG_HOLD`, returning the refusals counted while it was set.
    ///
    /// `now` is monotonic, so a wall-clock step neither releases nor
    /// prolongs the latch.
    pub(super) fn bound_tick(&self, now: Instant) -> Option<u64> {
        let below = self.lock_cache().entries.len() < self.cache_max_entries;
        let mut latch = self.lock_latch();
        if !latch.latched {
            return None;
        }
        if !below {
            latch.below_since = None;
            return None;
        }
        let since = *latch.below_since.get_or_insert(now);
        if now.saturating_duration_since(since) < BOUND_LOG_HOLD {
            return None;
        }
        let refused = latch.refused;
        *latch = BoundLatch::default();
        Some(refused)
    }

    /// The cached adverts open discovery should consider this sweep.
    ///
    /// The sweep enqueues at most `max` unconfigured authors, so this hands
    /// it a window: up to `max` unprotected entries drawn uniformly at random
    /// with `rng` (the caller's randomness), fresh on each call, so a fixed
    /// set of entries cannot hold the window and every cached author is
    /// reached over time. Protected entries come first and are listed beyond
    /// `max`, because the sweep acts on configured ones (it expedites their
    /// retry) without spending its enqueue budget. Authors in `skip` (those
    /// with an established link, and unconfigured authors already queued) are
    /// left out, since the sweep would pass over them and they would only
    /// take window slots. Our own advert and expired entries are left out
    /// too.
    pub(super) fn open_discovery_candidates(
        &self,
        max: usize,
        now_ms: u64,
        skip: &HashSet<String>,
        rng: &mut impl rand::Rng,
    ) -> Vec<(String, Vec<OverlayEndpointAdvert>, u64)> {
        let protected = self.lock_protected();
        let cache = self.lock_cache();
        let row = |entry: &CacheEntry| {
            (
                entry.cached.author_npub.clone(),
                entry.cached.advert.endpoints.clone(),
                entry.cached.created_at,
            )
        };
        let eligible = || {
            cache.entries.iter().filter(|(npub, entry)| {
                **npub != self.npub && entry.cached.valid_until_ms > now_ms && !skip.contains(*npub)
            })
        };
        let mut out: Vec<_> = eligible()
            .filter(|(npub, _)| protected.contains(*npub))
            .map(|(_, entry)| row(entry))
            .collect();
        out.extend(
            eligible()
                .filter(|(npub, _)| !protected.contains(*npub))
                .map(|(_, entry)| row(entry))
                .sample(rng, max),
        );
        out
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

    fn lock_protected(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.protected
            .lock()
            .expect("advert-machine protected mutex poisoned")
    }

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, AdvertCache> {
        self.cache
            .lock()
            .expect("advert-machine cache mutex poisoned")
    }

    fn lock_latch(&self) -> std::sync::MutexGuard<'_, BoundLatch> {
        self.latch
            .lock()
            .expect("advert-machine latch mutex poisoned")
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
    use rand::SeedableRng;
    use rand::rngs::StdRng;

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
    fn observe_advert_replaces_only_when_not_older() {
        let m = machine();
        let first = m.observe_advert("npub1peer", advert(vec![ep("1.2.3.4:9000")]), 100, 5000, 0);
        assert_eq!(first, AdvertAdmission::Admitted);
        // Older created_at -> not replaced.
        let older = m.observe_advert("npub1peer", advert(vec![ep("1.2.3.4:9001")]), 50, 5000, 0);
        assert_eq!(older, AdvertAdmission::Stale);
        assert_eq!(m.cached_created_at("npub1peer"), Some(100));
        // Newer created_at -> replaced.
        let newer = m.observe_advert("npub1peer", advert(vec![ep("1.2.3.4:9002")]), 200, 5000, 0);
        assert_eq!(newer, AdvertAdmission::Updated);
        assert_eq!(m.cached_created_at("npub1peer"), Some(200));
    }

    #[test]
    fn observe_advert_caches_our_own_advert_like_any_other() {
        let m = machine();
        // Our own advert is cached like any other; whether to log it as a peer
        // is the caller's decision.
        let own = m.observe_advert("npub1self", advert(vec![ep("1.2.3.4:9000")]), 100, 5000, 0);
        assert_eq!(own, AdvertAdmission::Admitted);
        assert_eq!(m.cached_created_at("npub1self"), Some(100));
    }

    #[test]
    fn prune_drops_expired_and_reports_no_eviction_under_cap() {
        let m = machine();
        m.insert_fetched("npub1a", cached("npub1a", 1, 1000), 0);
        m.insert_fetched("npub1b", cached("npub1b", 1, 3000), 0);
        // now=2000 -> npub1a expired, npub1b retained, under cap.
        assert_eq!(
            m.prune(2000),
            PruneReport {
                expired: 1,
                evicted: 0,
                retained: 1
            }
        );
        assert_eq!(m.cached_created_at("npub1a"), None);
        assert!(m.cached_created_at("npub1b").is_some());
    }

    #[test]
    fn prune_size_cap_evicts_the_most_recently_admitted_unprotected_entry() {
        let m = machine(); // cap = 3
        // The cache can only go above its cap through protection, so four
        // entries are admitted as protected and then lose it.
        m.set_protected(set(&["npub1a", "npub1b", "npub1c", "npub1d"]));
        m.insert_fetched("npub1a", cached("npub1a", 1, 1000), 0);
        m.insert_fetched("npub1b", cached("npub1b", 1, 2000), 0);
        m.insert_fetched("npub1c", cached("npub1c", 1, 3000), 0);
        m.insert_fetched("npub1d", cached("npub1d", 1, 4000), 0);
        m.set_protected(HashSet::new());
        let report = m.prune(500);
        assert_eq!(report.evicted, 1);
        assert_eq!(report.retained, 3);
        // The entry admitted last goes, whatever its horizon.
        assert_eq!(m.cached_created_at("npub1d"), None);
        assert!(m.cached_created_at("npub1a").is_some());
    }

    #[test]
    fn open_discovery_candidates_filters_self_and_expired() {
        let m = machine();
        m.insert_fetched("npub1self", cached("npub1self", 1, 9000), 0);
        m.insert_fetched("npub1peer", cached("npub1peer", 1, 9000), 0);
        m.insert_fetched("npub1stale", cached("npub1stale", 1, 1000), 0);
        let out =
            m.open_discovery_candidates(10, 2000, &HashSet::new(), &mut StdRng::seed_from_u64(1));
        assert_eq!(out.len(), 1, "only the valid non-self peer survives");
        assert_eq!(out[0].0, "npub1peer");
    }

    #[test]
    fn open_discovery_candidates_respects_max() {
        let m = machine();
        for i in 0..5 {
            let npub = format!("npub1p{i}");
            m.insert_fetched(&npub, cached(&npub, 1, 9000), 0);
        }
        assert_eq!(
            m.open_discovery_candidates(2, 1000, &HashSet::new(), &mut StdRng::seed_from_u64(1))
                .len(),
            2
        );
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

    // --- admission under a full cache ------------------------------------

    const T0: u64 = 1_000_000;

    fn capped(cap: usize) -> AdvertMachine {
        AdvertMachine::new("npub1self".to_string(), true, 10_000_000, cap)
    }

    fn observe(m: &AdvertMachine, npub: &str, valid_until_ms: u64, now_ms: u64) {
        let _ = m.observe_advert(
            npub,
            advert(vec![ep("1.2.3.4:9000")]),
            1,
            valid_until_ms,
            now_ms,
        );
    }

    fn fetched(m: &AdvertMachine, npub: &str, valid_until_ms: u64, now_ms: u64) {
        let _ = m.insert_fetched(npub, cached(npub, 1, valid_until_ms), now_ms);
    }

    fn held(m: &AdvertMachine, npubs: &[&str]) -> usize {
        npubs
            .iter()
            .filter(|npub| m.cached_created_at(npub).is_some())
            .count()
    }

    fn set(npubs: &[&str]) -> HashSet<String> {
        npubs.iter().map(|npub| npub.to_string()).collect()
    }

    #[test]
    fn an_advert_flood_under_new_keys_cannot_evict_an_honest_cached_advert() {
        let m = capped(4);
        observe(&m, "npub1honest", T0 + 3_600_000, T0);
        let flood = ["npub1x1", "npub1x2", "npub1x3", "npub1x4"];
        for npub in flood {
            observe(&m, npub, T0 + 7_200_000, T0);
        }
        let _ = m.prune(T0 + 1);

        assert!(m.cached_created_at("npub1honest").is_some());
        let mut all = flood.to_vec();
        all.push("npub1honest");
        assert_eq!(held(&m, &all), 4);
    }

    #[test]
    fn a_fetched_advert_from_a_new_author_is_refused_when_the_cache_is_full() {
        let m = capped(4);
        let honest = ["npub1h0", "npub1h1", "npub1h2", "npub1h3"];
        for (i, npub) in honest.iter().enumerate() {
            observe(&m, npub, T0 + 3_600_000 + i as u64, T0);
        }
        fetched(&m, "npub1attacker", T0 + 7_200_000, T0);
        let _ = m.prune(T0 + 1);

        assert_eq!(held(&m, &honest), 4, "every honest entry stays cached");
        assert!(m.cached_created_at("npub1attacker").is_none());

        // Control: with room, the same author is cached, so the refusal above
        // is the full cache and not the npub.
        let roomy = capped(4);
        fetched(&roomy, "npub1attacker", T0 + 7_200_000, T0);
        assert!(roomy.cached_created_at("npub1attacker").is_some());
    }

    #[test]
    fn a_configured_author_arriving_at_a_cache_full_of_strangers_is_admitted() {
        let m = capped(4);
        let strangers = ["npub1u1", "npub1u2", "npub1u3", "npub1u4"];
        for (i, npub) in strangers.iter().enumerate() {
            observe(&m, npub, T0 + 7_200_000 + i as u64, T0);
        }
        m.set_protected(set(&["npub1configured"]));
        observe(&m, "npub1configured", T0 + 3_600_000, T0);
        let _ = m.prune(T0 + 1);

        assert!(m.cached_created_at("npub1configured").is_some());
        let mut all = strangers.to_vec();
        all.push("npub1configured");
        assert_eq!(held(&m, &all), 4);
        assert!(
            m.cached_created_at("npub1u4").is_none(),
            "the most recently admitted stranger makes room"
        );
        assert!(m.cached_created_at("npub1u1").is_some());
    }

    #[test]
    fn an_over_cap_prune_keeps_a_protected_entry_with_the_soonest_horizon() {
        let m = capped(3);
        m.set_protected(set(&["npub1p", "npub1a", "npub1b", "npub1c"]));
        fetched(&m, "npub1a", 2000, 0);
        fetched(&m, "npub1b", 3000, 0);
        fetched(&m, "npub1c", 4000, 0);
        fetched(&m, "npub1p", 1000, 0);
        m.set_protected(set(&["npub1p"]));
        let _ = m.prune(500);

        assert!(m.cached_created_at("npub1p").is_some());
        assert!(m.cached_created_at("npub1c").is_none());
        assert!(m.cached_created_at("npub1a").is_some());
        assert!(m.cached_created_at("npub1b").is_some());
        assert_eq!(held(&m, &["npub1p", "npub1a", "npub1b", "npub1c"]), 3);
    }

    #[test]
    fn a_key_cycled_through_a_link_cannot_evict_honest_cached_adverts() {
        let m = capped(4);
        observe(&m, "npub1h1", T0 + 3_600_000, T0);
        observe(&m, "npub1h2", T0 + 3_600_001, T0);
        observe(&m, "npub1a1", T0 + 7_200_000, T0);
        observe(&m, "npub1a2", T0 + 7_200_001, T0);
        let mut all: Vec<String> = ["npub1h1", "npub1h2", "npub1a1", "npub1a2"]
            .iter()
            .map(|npub| npub.to_string())
            .collect();
        for i in 1..=10u64 {
            let key = format!("npub1k{i}");
            m.set_protected(set(&[key.as_str()]));
            observe(&m, &key, T0 + 7_200_100 + i, T0);
            m.set_protected(HashSet::new());
            let _ = m.prune(T0 + 1);
            all.push(key);
        }

        assert!(m.cached_created_at("npub1h1").is_some());
        assert!(m.cached_created_at("npub1h2").is_some());
        let all: Vec<&str> = all.iter().map(String::as_str).collect();
        assert_eq!(held(&m, &all), 4);
    }

    /// Keys linked at the same time against a cache of honest entries only
    /// each displace the newest honest entry, and those slots stay with the
    /// keys after the links drop; later cycling displaces only those keys.
    /// So an attacker's lasting reach is the number of links it holds at
    /// once, which `max_peers` bounds.
    #[test]
    fn concurrently_linked_keys_displace_one_honest_advert_each_and_no_more() {
        let m = capped(4);
        for (i, npub) in ["npub1h1", "npub1h2", "npub1h3", "npub1h4"]
            .iter()
            .enumerate()
        {
            observe(&m, npub, T0 + 3_600_000 + i as u64, T0);
        }
        m.set_protected(set(&["npub1k1", "npub1k2"]));
        observe(&m, "npub1k1", T0 + 7_200_000, T0);
        observe(&m, "npub1k2", T0 + 7_200_001, T0);
        m.set_protected(HashSet::new());
        let _ = m.prune(T0 + 1);
        assert!(m.cached_created_at("npub1h3").is_none());
        assert!(m.cached_created_at("npub1h4").is_none());

        for i in 3..=12u64 {
            let key = format!("npub1k{i}");
            m.set_protected(set(&[key.as_str()]));
            observe(&m, &key, T0 + 7_200_100 + i, T0);
            m.set_protected(HashSet::new());
            let _ = m.prune(T0 + 1);
        }
        assert!(m.cached_created_at("npub1h1").is_some());
        assert!(m.cached_created_at("npub1h2").is_some());
        assert_eq!(held(&m, &["npub1h1", "npub1h2"]), 2);
    }

    #[test]
    fn linked_authors_take_no_open_discovery_slot_and_configured_ones_are_listed_beyond_it() {
        let m = capped(256);
        let linked: Vec<String> = (0..70).map(|i| format!("npub1linked{i}")).collect();
        let configured: Vec<String> = (0..10).map(|i| format!("npub1configured{i}")).collect();
        let open: Vec<String> = (0..20).map(|i| format!("npub1open{i}")).collect();
        m.set_protected(linked.iter().chain(configured.iter()).cloned().collect());
        for npub in linked.iter().chain(configured.iter()).chain(open.iter()) {
            observe(&m, npub, T0 + 3_600_000, T0);
        }
        let skip: HashSet<String> = linked.iter().cloned().collect();

        let out = m.open_discovery_candidates(64, T0, &skip, &mut StdRng::seed_from_u64(1));
        let got: HashSet<String> = out.into_iter().map(|(npub, _, _)| npub).collect();
        let want: HashSet<String> = configured.iter().chain(open.iter()).cloned().collect();
        assert_eq!(got, want);
    }

    #[test]
    fn every_honest_advert_cached_before_a_flood_reaches_the_open_discovery_window() {
        let m = capped(256);
        let honest: Vec<String> = (0..8).map(|i| format!("npub1honest{i}")).collect();
        let flood: Vec<String> = (0..248).map(|i| format!("npub1flood{i}")).collect();
        for npub in honest.iter().chain(flood.iter()) {
            observe(&m, npub, T0 + 3_600_000, T0);
        }
        for npub in &flood {
            observe(&m, npub, T0 + 3_600_000, T0);
        }

        let mut rng = StdRng::seed_from_u64(7);
        let mut seen: HashSet<String> = HashSet::new();
        for _ in 0..200 {
            for (npub, _, _) in m.open_discovery_candidates(64, T0, &HashSet::new(), &mut rng) {
                seen.insert(npub);
            }
            for npub in &flood {
                observe(&m, npub, T0 + 3_600_000, T0);
            }
        }
        let missed: Vec<&String> = honest.iter().filter(|npub| !seen.contains(*npub)).collect();
        assert!(
            missed.is_empty(),
            "never offered to open discovery: {missed:?}"
        );
    }

    #[test]
    fn a_new_author_is_admitted_while_the_cache_has_room_and_its_republish_replaces_it() {
        let m = capped(4);
        let first = m.observe_advert(
            "npub1new",
            advert(vec![ep("1.2.3.4:9000")]),
            10,
            T0 + 3_600_000,
            T0,
        );
        assert_eq!(first, AdvertAdmission::Admitted);
        let again = m.observe_advert(
            "npub1new",
            advert(vec![ep("1.2.3.4:9001")]),
            20,
            T0 + 3_600_000,
            T0,
        );
        assert_eq!(again, AdvertAdmission::Updated);
        assert_eq!(m.cached_created_at("npub1new"), Some(20));
    }

    #[test]
    fn a_linked_author_keeps_its_slot_through_a_flood_and_loses_protection_when_unlinked() {
        let m = capped(3);
        observe(&m, "npub1s1", 2000, 0);
        observe(&m, "npub1s2", 3000, 0);
        m.set_protected(set(&["npub1linked"]));
        observe(&m, "npub1linked", 1000, 0);
        for npub in ["npub1s3", "npub1s4"] {
            let refused = m.observe_advert(npub, advert(vec![ep("1.2.3.4:9000")]), 1, 9000, 0);
            assert!(matches!(refused, AdvertAdmission::Refused { .. }));
        }
        let _ = m.prune(500);
        assert!(m.cached_created_at("npub1linked").is_some());

        // The link drops and a configured peer appears in the same push.
        m.set_protected(set(&["npub1configured"]));
        observe(&m, "npub1configured", 5000, 0);
        assert!(
            m.cached_created_at("npub1linked").is_none(),
            "the formerly linked author is now the newest unprotected entry"
        );
        assert!(m.cached_created_at("npub1configured").is_some());
        assert!(m.cached_created_at("npub1s1").is_some());
        assert!(m.cached_created_at("npub1s2").is_some());
    }

    #[test]
    fn a_cache_full_of_expired_adverts_admits_a_new_unconfigured_author() {
        let m = capped(4);
        for (i, npub) in ["npub1e1", "npub1e2", "npub1e3", "npub1e4"]
            .iter()
            .enumerate()
        {
            observe(&m, npub, 1000 + i as u64, 0);
        }
        let now = 10_000;
        let admitted = m.observe_advert(
            "npub1new",
            advert(vec![ep("1.2.3.4:9000")]),
            1,
            now + 3_600_000,
            now,
        );
        assert_eq!(admitted, AdvertAdmission::Admitted);
        assert!(m.cached_created_at("npub1new").is_some());
    }

    #[test]
    fn the_cache_full_warning_fires_once_and_releases_after_a_minute_below_the_cap() {
        let m = capped(2);
        observe(&m, "npub1a", T0 + 3_600_000, T0);
        observe(&m, "npub1b", T0 + 3_600_000, T0);
        let offer = |npub: &str| {
            m.observe_advert(
                npub,
                advert(vec![ep("1.2.3.4:9000")]),
                1,
                T0 + 3_600_000,
                T0,
            )
        };
        assert_eq!(
            offer("npub1x"),
            AdvertAdmission::Refused {
                first_at_bound: true
            }
        );
        assert_eq!(
            offer("npub1y"),
            AdvertAdmission::Refused {
                first_at_bound: false
            }
        );

        let t = Instant::now();
        assert_eq!(m.bound_tick(t), None, "still at the cap");
        m.remove("npub1a");
        assert_eq!(m.bound_tick(t), None);
        assert_eq!(m.bound_tick(t + Duration::from_millis(59_999)), None);
        assert_eq!(m.bound_tick(t + Duration::from_millis(60_000)), Some(2));
        assert_eq!(
            m.bound_tick(t + Duration::from_millis(120_000)),
            None,
            "released once"
        );
    }
}
