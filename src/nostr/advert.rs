//! Synchronous decision core for the Nostr overlay-advert lifecycle.
//!
//! `AdvertMachine` owns the advert-related state that previously lived
//! directly on `NostrRendezvous` — the peer advert cache and the local
//! advert we publish — and hosts the *decision* logic for publishing,
//! caching, fetching, and pruning adverts.
//!
//! Following the sans-IO shape used by `failure_state`, every method here
//! is synchronous, performs no network I/O and no `.await`, holds its
//! state behind `std::sync::Mutex`, and takes the current time as an
//! explicit `now_ms: u64` input rather than reading a clock. The async
//! driver on `NostrRendezvous` reads the clock at the call site, invokes
//! these methods, and performs the actual relay I/O (`send_event_to`,
//! `fetch_events_from`, gift-wrap crypto), event signing, and `Notify`
//! wakeups described by the returned decisions. No NIP-09 deletion is ever
//! sent for an advert: a stopped advert is left to NIP-40 expiration.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nostr::prelude::Event;
use rand::seq::IteratorRandom;

use super::runtime::{NostrRendezvous, endpoint_advert_is_publicly_usable};
use super::types::{
    ADVERT_IDENTIFIER, ADVERT_VERSION, BootstrapError, CachedOverlayAdvert, OverlayAdvert,
    OverlayEndpointAdvert,
};

/// What the async driver should do to satisfy a publish request. Returned
/// by [`AdvertMachine::plan_publish`]; the machine performs the pure
/// decision (which advert body, or nothing) and the driver executes the
/// corresponding relay I/O.
#[derive(Debug, Clone)]
pub(super) enum PublishPlan {
    /// Nothing to publish (advertising disabled, no local advert yet, or
    /// the advert has no publicly usable endpoints).
    Nothing,
    /// Publish this fully-prepared advert body. The driver builds the
    /// tags/expiration, signs, and sends.
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
    /// Entries dropped because their validity horizon and the lapse grace
    /// after it had both passed.
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
///
/// An entry past its validity horizon is *lapsed* for `lapse_grace_ms`: it
/// still holds its slot and counts against the cap, but serves nothing, and
/// its author's next advert replaces it as an update that keeps its
/// `admitted_seq`. Only after the grace is the entry dropped. Without the
/// grace, an honest author that missed one republish during a flood that
/// keeps the cache full would see its freed slot go to the next flood key
/// and its next advert refused as a newcomer's.
#[derive(Default)]
struct AdvertCache {
    entries: HashMap<String, CacheEntry>,
    next_seq: u64,
    lapse_grace_ms: u64,
}

impl AdvertCache {
    /// Drop every entry whose validity horizon plus the lapse grace is not
    /// after `now_ms`, and return how many went.
    fn drop_expired(&mut self, now_ms: u64) -> usize {
        let grace = self.lapse_grace_ms;
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| entry.cached.valid_until_ms.saturating_add(grace) > now_ms);
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
        }
    }

    /// Keep an entry that passes its validity horizon in the cache, lapsed,
    /// for `grace_ms` more (see [`AdvertCache`]). The runtime passes one
    /// republish interval of this node (`advert_refresh_secs`). That is a
    /// limit: an honest author republishing less often than this node does
    /// can still lose its slot during a flood. Without this call the grace
    /// is zero and an entry is dropped at its horizon.
    pub(super) fn with_lapse_grace(mut self, grace_ms: u64) -> Self {
        self.cache
            .get_mut()
            .expect("advert-machine cache mutex poisoned")
            .lapse_grace_ms = grace_ms;
        self
    }

    /// The lapse grace, for tests that check what the runtime configured.
    #[cfg(test)]
    pub(super) fn lapse_grace_ms(&self) -> u64 {
        self.lock_cache().lapse_grace_ms
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
    /// horizon and lapse grace; then, while the cache is above its cap, removes unprotected
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
    /// An author already cached, lapsed or not, has its entry replaced when
    /// this advert's `created_at` is not older than the cached one, keeping
    /// its admission order. A new author is admitted while the cache has
    /// room. When the cache is full, entries past their lapse grace are
    /// dropped first; then a protected author (a configured peer,
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
    /// if present and not past its horizon at `now_ms`, `None` if the driver
    /// must fetch from relays. A lapsed entry is never served.
    pub(super) fn cached_advert(&self, peer_npub: &str, now_ms: u64) -> Option<OverlayAdvert> {
        self.lock_cache()
            .entries
            .get(peer_npub)
            .filter(|entry| entry.cached.valid_until_ms > now_ms)
            .map(|entry| entry.cached.advert.clone())
    }

    /// The `created_at` of a cached advert, if any, lapsed entries included.
    /// Used by the stale-check refetch path to decide whether a relay result
    /// is newer; it serves no advert.
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
    /// take window slots. Our own advert and entries past their horizon,
    /// lapsed ones included, are left out too.
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

    /// Build the publish decision: which advert body to publish, or nothing.
    /// Pure logic — the driver performs the relay I/O and event signing.
    pub(super) fn plan_publish(&self) -> Result<PublishPlan, BootstrapError> {
        if !self.advertise {
            return Ok(PublishPlan::Nothing);
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
}

#[cfg(test)]
#[path = "tests/advert.rs"]
mod tests;
