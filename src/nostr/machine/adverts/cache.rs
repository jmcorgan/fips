//! The peer advert cache: which authors' adverts the node holds, under a
//! size cap that a flood of new keys cannot use to evict an honest author,
//! and which of them open discovery considers.
//!
//! Every method here is synchronous, performs no I/O and no `.await`, and
//! takes the current time as an argument: wall-clock `now_ms: u64` for the
//! adverts' horizons, and a monotonic instant of any `fips_core::time::Instant`
//! type for the cache-full log latch. It holds no lock; the runtime keeps the
//! cache behind one `std::sync::Mutex`. The runtime reads and validates the
//! Nostr event, offers the advert here, and logs what the returned decision
//! says.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::time::Duration;

use fips_core::entropy::EntropySource;
use fips_core::time::Instant;
use fips_core::utils::hash::{HashMap, KeyedHasher};

use super::super::types::{CachedOverlayAdvert, OverlayAdvert, OverlayEndpointAdvert};

/// How long the advert cache must stay below its cap before the cache-full
/// warning is re-armed. An advert flood that pushes the cache across its cap
/// once per advert then produces at most two lines a minute: the warning when
/// the cap is first reached and the release line once the hold has passed.
const BOUND_LOG_HOLD: Duration = Duration::from_secs(60);

/// What the cache did with one advert offered to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvertAdmission {
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
pub struct PruneReport {
    /// Entries dropped because their validity horizon and the lapse grace
    /// after it had both passed.
    pub expired: usize,
    /// Unprotected entries removed to bring the cache back to its cap.
    pub evicted: usize,
    /// Entries left in the cache.
    pub retained: usize,
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
struct AdvertCache {
    entries: HashMap<String, CacheEntry>,
    next_seq: u64,
    lapse_grace_ms: u64,
}

impl AdvertCache {
    /// An empty cache with no lapse grace, its map keyed with `hasher`.
    fn new(hasher: KeyedHasher) -> Self {
        Self {
            entries: HashMap::with_hasher(hasher),
            next_seq: 0,
            lapse_grace_ms: 0,
        }
    }

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
    fn newest_unprotected(&self, protected: &BTreeSet<String>) -> Option<String> {
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
struct BoundLatch<I> {
    latched: bool,
    /// Refusals since the latch was set, the first included.
    refused: u64,
    /// When the cache was first seen below its cap while latched.
    below_since: Option<I>,
}

impl<I> Default for BoundLatch<I> {
    /// A latch that is not set.
    fn default() -> Self {
        Self {
            latched: false,
            refused: 0,
            below_since: None,
        }
    }
}

/// The peer advert cache, the authors it protects, and its cache-full log
/// latch.
pub struct Cache<I> {
    /// Our own npub. Used to keep self-authored adverts out of open
    /// discovery.
    npub: String,
    /// Size cap for the peer advert cache.
    cache_max_entries: usize,
    /// Authors whose adverts the cache keeps when it is full: the configured
    /// peers and the authors with a currently established link, as the node
    /// last pushed them. Only ever tested for membership.
    protected: BTreeSet<String>,
    /// Peer advert cache keyed by author npub.
    cache: AdvertCache,
    /// The cache-full log latch.
    latch: BoundLatch<I>,
}

impl<I: Instant> Cache<I> {
    /// An empty cache of at most `cache_max_entries` entries (protected
    /// authors aside), owned by `npub`, its map keyed with `hasher`.
    pub fn new(npub: String, cache_max_entries: usize, hasher: KeyedHasher) -> Self {
        Self {
            npub,
            cache_max_entries,
            protected: BTreeSet::new(),
            cache: AdvertCache::new(hasher),
            latch: BoundLatch::default(),
        }
    }

    /// Keep an entry that passes its validity horizon in the cache, lapsed,
    /// for `grace_ms` more (see [`AdvertCache`]). The runtime passes one
    /// republish interval of this node (`advert_refresh_secs`). That is a
    /// limit: an honest author republishing less often than this node does
    /// can still lose its slot during a flood. Without this call the grace
    /// is zero and an entry is dropped at its horizon.
    pub fn with_lapse_grace(mut self, grace_ms: u64) -> Self {
        self.cache.lapse_grace_ms = grace_ms;
        self
    }

    /// The lapse grace, for tests that check what the runtime configured.
    #[cfg(test)]
    pub fn lapse_grace_ms(&self) -> u64 {
        self.cache.lapse_grace_ms
    }

    /// Replace the set of authors whose adverts the cache protects.
    pub fn set_protected(&mut self, npubs: impl IntoIterator<Item = String>) {
        self.protected = npubs.into_iter().collect();
    }

    /// The set of protected authors, for tests that check what the node
    /// pushed.
    #[cfg(test)]
    pub fn protected(&self) -> &BTreeSet<String> {
        &self.protected
    }

    // --- cache: prune / observe / fetch --------------------------------

    /// TTL and size-cap maintenance. Drops entries past their validity
    /// horizon and lapse grace; then, while the cache is above its cap, removes unprotected
    /// entries, the most recently admitted first. Protected entries are never
    /// removed before they expire, so the cache can stay above its cap by
    /// protected entries alone.
    pub fn prune(&mut self, now_ms: u64) -> PruneReport {
        let protected = &self.protected;
        let cache = &mut self.cache;
        let expired = cache.drop_expired(now_ms);
        let mut evicted = 0;
        while cache.entries.len() > self.cache_max_entries {
            let Some(victim) = cache.newest_unprotected(protected) else {
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
    pub fn observe_advert(
        &mut self,
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
    pub fn cached_advert(&self, peer_npub: &str, now_ms: u64) -> Option<OverlayAdvert> {
        self.cache
            .entries
            .get(peer_npub)
            .filter(|entry| entry.cached.valid_until_ms > now_ms)
            .map(|entry| entry.cached.advert.clone())
    }

    /// The `created_at` of a cached advert, if any, lapsed entries included.
    /// Used by the stale-check refetch path to decide whether a relay result
    /// is newer; it serves no advert.
    pub fn cached_created_at(&self, peer_npub: &str) -> Option<u64> {
        self.cache
            .entries
            .get(peer_npub)
            .map(|entry| entry.cached.created_at)
    }

    /// Offer a freshly fetched advert to the cache (fetch-miss path and
    /// stale-check refresh), under the same rule as [`Self::observe_advert`]:
    /// a configured or linked author is always cached, anyone else only
    /// while the cache has room.
    pub fn insert_fetched(
        &mut self,
        peer_npub: &str,
        cached: CachedOverlayAdvert,
        now_ms: u64,
    ) -> AdvertAdmission {
        self.admit(peer_npub, cached, now_ms)
    }

    /// Remove a peer's cached advert (stale-check eviction).
    pub fn remove(&mut self, peer_npub: &str) {
        self.cache.entries.remove(peer_npub);
    }

    /// The admission rule shared by the notify loop and the fetch paths.
    fn admit(&mut self, npub: &str, cached: CachedOverlayAdvert, now_ms: u64) -> AdvertAdmission {
        let protected = &self.protected;
        let cache = &mut self.cache;
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
                && let Some(victim) = cache.newest_unprotected(protected)
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
        let latch = &mut self.latch;
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
    pub fn bound_tick(&mut self, now: I) -> Option<u64> {
        let below = self.cache.entries.len() < self.cache_max_entries;
        let latch = &mut self.latch;
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
    /// from `E` (the caller's entropy), fresh on each call, so a fixed
    /// set of entries cannot hold the window and every cached author is
    /// reached over time. Protected entries come first and are listed beyond
    /// `max`, because the sweep acts on configured ones (it expedites their
    /// retry) without spending its enqueue budget. Authors `skip` names (those
    /// with an established link, and unconfigured authors already queued) are
    /// left out, since the sweep would pass over them and they would only
    /// take window slots. Our own advert and entries past their horizon,
    /// lapsed ones included, are left out too.
    pub fn open_discovery_candidates<E: EntropySource>(
        &self,
        max: usize,
        now_ms: u64,
        skip: impl Fn(&str) -> bool,
    ) -> Vec<(String, Vec<OverlayEndpointAdvert>, u64)> {
        let protected = &self.protected;
        let cache = &self.cache;
        let row = |entry: &CacheEntry| {
            (
                entry.cached.author_npub.clone(),
                entry.cached.advert.endpoints.clone(),
                entry.cached.created_at,
            )
        };
        let eligible = || {
            cache.entries.iter().filter(|(npub, entry)| {
                **npub != self.npub && entry.cached.valid_until_ms > now_ms && !skip(npub)
            })
        };
        let mut out: Vec<_> = eligible()
            .filter(|(npub, _)| protected.contains(*npub))
            .map(|(_, entry)| row(entry))
            .collect();
        out.extend(sample::<E, _>(
            eligible()
                .filter(|(npub, _)| !protected.contains(*npub))
                .map(|(_, entry)| row(entry)),
            max,
        ));
        out
    }
}

/// Up to `amount` items of `items`, chosen uniformly at random from `E` by
/// reservoir sampling: every item has the same chance of being chosen, and
/// the order of the chosen items is not random.
fn sample<E: EntropySource, T>(mut items: impl Iterator<Item = T>, amount: usize) -> Vec<T> {
    let mut reservoir: Vec<T> = items.by_ref().take(amount).collect();
    if amount > 0 && reservoir.len() == amount {
        for (i, item) in items.enumerate() {
            let k = below::<E>(i + 1 + amount);
            if let Some(slot) = reservoir.get_mut(k) {
                *slot = item;
            }
        }
    }
    reservoir
}

/// A uniformly random index below `n` (which must not be 0), from `E`.
///
/// A draw from the top of the `u64` range that would favour the low
/// indices is discarded and drawn again.
fn below<E: EntropySource>(n: usize) -> usize {
    let n = n as u64;
    // 2^64 mod n: the draws at the top of the range that would bias the result.
    let biased = (u64::MAX % n + 1) % n;
    loop {
        let mut bytes = [0u8; 8];
        E::fill(&mut bytes);
        let draw = u64::from_le_bytes(bytes);
        if biased == 0 || draw < biased.wrapping_neg() {
            return (draw % n) as usize;
        }
    }
}

#[cfg(test)]
#[path = "tests/cache.rs"]
mod tests;
