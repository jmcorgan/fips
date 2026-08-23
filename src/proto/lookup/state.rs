//! Mesh lookup subsystem state owned by [`Node`](crate::node::Node).
//!
//! Groups the four lookup-related state fields (recent-request dedup
//! cache, in-flight lookups, originator-side backoff, transit-side forward
//! rate limiter) behind a single struct so the lookup handlers can
//! evolve toward a sans-IO core without threading four fields through
//! `Node`.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use super::limits::{LookupBackoff, LookupForwardRateLimiter};
use crate::NodeAddr;

/// Recent request tracking for dedup and reverse-path forwarding.
///
/// When a LookupRequest is forwarded through a node, the node stores the
/// request_id and which peer sent it. When the corresponding LookupResponse
/// arrives, it's forwarded back to that peer (reverse-path forwarding).
/// The `response_forwarded` flag prevents response routing loops.
#[derive(Clone, Debug)]
pub(crate) struct RecentRequest {
    /// The peer who sent this request to us.
    pub(crate) from_peer: NodeAddr,
    /// When we received this request (Unix milliseconds).
    pub(crate) timestamp_ms: u64,
    /// Whether we've already forwarded a response for this request.
    /// Prevents response routing loops when convergent request paths
    /// create bidirectional entries in recent_requests.
    pub(crate) response_forwarded: bool,
}

impl RecentRequest {
    pub(crate) fn new(from_peer: NodeAddr, timestamp_ms: u64) -> Self {
        Self {
            from_peer,
            timestamp_ms,
            response_forwarded: false,
        }
    }

    /// Check if this entry has expired (older than expiry_ms).
    pub(crate) fn is_expired(&self, current_time_ms: u64, expiry_ms: u64) -> bool {
        current_time_ms.saturating_sub(self.timestamp_ms) > expiry_ms
    }
}

/// How many outstanding `request_id`s one pending lookup remembers.
///
/// Bounds the per-target correlator at eight u64s. The retry ladder
/// (`node.discovery.attempt_timeouts_secs`) is operator configuration and can
/// be longer than this, so the recorder evicts the oldest id rather than
/// refusing the newest: dropping the newest would discard the id most likely
/// to be answered and fail a healthy lookup. Raising this costs eight bytes
/// per extra attempt on every pending target and widens the set of ids a late
/// response may still match; lowering it means a reply to an early attempt on
/// a long ladder is dropped as unsolicited.
const MAX_RECORDED_IDS: usize = 8;

/// Tracks a pending lookup with retry state.
pub struct PendingLookup {
    /// When the lookup was first initiated.
    pub initiated_ms: u64,
    /// When the last attempt was sent.
    pub last_sent_ms: u64,
    /// Current attempt number (1 = initial, 2 = first retry, ...).
    pub attempt: u8,
    /// `request_id`s issued for this target, oldest first, capped at
    /// [`MAX_RECORDED_IDS`]. A response is only acted on when it carries one
    /// of these, which is what makes the accept path solicited. The entry
    /// itself is dropped at ladder timeout, so this set needs no expiry.
    pub ids: Vec<u64>,
}

impl PendingLookup {
    pub fn new(now_ms: u64) -> Self {
        Self {
            initiated_ms: now_ms,
            last_sent_ms: now_ms,
            attempt: 1,
            ids: Vec::new(),
        }
    }

    /// Remember a `request_id` just put on the wire for this target.
    pub fn record(&mut self, request_id: u64) {
        if self.ids.contains(&request_id) {
            return;
        }
        if self.ids.len() >= MAX_RECORDED_IDS {
            self.ids.remove(0);
        }
        self.ids.push(request_id);
    }

    /// Whether `request_id` is one this node issued for this target.
    pub fn matches(&self, request_id: u64) -> bool {
        self.ids.contains(&request_id)
    }
}

/// Floor under one link peer's share of the dedup cache.
///
/// A peer's share is the cache size divided by the current link-peer count,
/// and this is what stops that share collapsing to nothing on a node with
/// very many links. It is a cap and not a reservation: shares can sum past
/// the cache size, in which case the peer holding the most entries pays for
/// the next admission. Raising it lets one busy neighbour hold more of the
/// cache; lowering it clips a genuine transit burst.
pub(crate) const MIN_RECENT_PER_PEER: usize = 64;

/// Mesh lookup subsystem state.
pub(crate) struct Lookup {
    /// Recent lookup requests (dedup + reverse-path forwarding).
    /// Maps request_id → RecentRequest.
    pub(crate) recent_requests: BTreeMap<u64, RecentRequest>,
    /// Arrival-order index over `recent_requests`, partitioned by the link
    /// peer each request arrived from. The cache is full-then-evict rather
    /// than full-then-refuse, and this is what lets an eviction be charged
    /// to the peer that filled the cache instead of to whoever happens to be
    /// oldest. `now_ms` is nondecreasing across inserts, so each deque is in
    /// arrival order and its front is that peer's oldest entry.
    ///
    /// The index and the cache are two containers where there was one, so
    /// they must be maintained together: every mutation of `recent_requests`
    /// goes through [`Lookup::record_recent`], [`Lookup::evict_oldest_from`]
    /// or [`Lookup::purge_recent`], which keep the two level. A drifted index
    /// evicts the wrong entry, or none at all.
    pub(crate) recent_by_peer: BTreeMap<NodeAddr, VecDeque<u64>>,
    /// Tracks in-flight lookups. Maps target NodeAddr to the
    /// initiation timestamp (Unix ms). Prevents duplicate flood queries.
    pub(crate) pending_lookups: BTreeMap<NodeAddr, PendingLookup>,
    /// Backoff for failed lookups (originator-side).
    pub(crate) backoff: LookupBackoff,
    /// Rate limiter for forwarded lookup requests (transit-side).
    pub(crate) forward_limiter: LookupForwardRateLimiter,
}

impl Lookup {
    /// Create mesh lookup state with the given backoff and forward limiter.
    ///
    /// The two limiters are constructed by the caller so each `Node`
    /// constructor can supply its own configured/default variant, matching
    /// the pre-refactor initialization exactly.
    pub(crate) fn new(backoff: LookupBackoff, forward_limiter: LookupForwardRateLimiter) -> Self {
        Self {
            recent_requests: BTreeMap::new(),
            recent_by_peer: BTreeMap::new(),
            pending_lookups: BTreeMap::new(),
            backoff,
            forward_limiter,
        }
    }

    /// One link peer's share of the dedup cache at the current peer count.
    ///
    /// The share tracks the peer count rather than being pinned to a number
    /// a many-peer node outgrows, with [`MIN_RECENT_PER_PEER`] as its floor.
    /// `peer_count` is supplied by the caller: the core is sans-IO and has no
    /// view of the live peer table.
    pub(crate) fn peer_share(max_recent: usize, peer_count: usize) -> usize {
        (max_recent / peer_count.max(1)).max(MIN_RECENT_PER_PEER)
    }

    /// How many cached entries `peer` currently holds.
    pub(crate) fn peer_entries(&self, peer: &NodeAddr) -> usize {
        self.recent_by_peer.get(peer).map_or(0, VecDeque::len)
    }

    /// The link peer holding the most cached entries, if any.
    ///
    /// Ties resolve to the highest `NodeAddr`, because `max_by_key` keeps the
    /// last maximum and the index is ordered. Arbitrary but deterministic:
    /// nothing about the policy depends on which of two equally heavy peers
    /// pays, only that the choice does not vary run to run.
    pub(crate) fn heaviest_peer(&self) -> Option<NodeAddr> {
        self.recent_by_peer
            .iter()
            .max_by_key(|(_, ids)| ids.len())
            .map(|(peer, _)| *peer)
    }

    /// Record a request for dedup and reverse-path forwarding, indexing it
    /// under the link peer it arrived from.
    ///
    /// The caller has already established that `request_id` is not cached; a
    /// duplicate must not reach here, or the index would hold it twice.
    pub(crate) fn record_recent(&mut self, request_id: u64, from: NodeAddr, now_ms: u64) {
        self.recent_requests
            .insert(request_id, RecentRequest::new(from, now_ms));
        self.recent_by_peer
            .entry(from)
            .or_default()
            .push_back(request_id);
    }

    /// Drop `peer`'s oldest cached entry, returning the evicted `request_id`.
    ///
    /// Returns `None` when the peer holds nothing, which the eviction policy
    /// treats as "no room could be made" rather than as an error.
    pub(crate) fn evict_oldest_from(&mut self, peer: &NodeAddr) -> Option<u64> {
        let ids = self.recent_by_peer.get_mut(peer)?;
        let evicted = ids.pop_front()?;
        if ids.is_empty() {
            self.recent_by_peer.remove(peer);
        }
        self.recent_requests.remove(&evicted);
        Some(evicted)
    }

    /// Purge expired dedup entries, from the cache and the index together.
    ///
    /// The index is rebuilt from what survived rather than aged on its own
    /// clock, so the two cannot drift apart: an id is indexed if and only if
    /// the cache still holds it, and a peer disappears from the index when
    /// its last entry does.
    pub(crate) fn purge_recent(&mut self, now_ms: u64, expiry_ms: u64) {
        self.recent_requests
            .retain(|_, entry| !entry.is_expired(now_ms, expiry_ms));
        let recent = &self.recent_requests;
        self.recent_by_peer.retain(|_, ids| {
            ids.retain(|id| recent.contains_key(id));
            !ids.is_empty()
        });
    }

    /// Reset lookup backoff on topology changes. Returns the number of
    /// entries cleared (0 if already empty) so the shell can log the reset —
    /// observability stays out of the pure core.
    pub(crate) fn reset_backoff(&mut self) -> usize {
        if self.backoff.is_empty() {
            return 0;
        }
        let cleared = self.backoff.entry_count();
        self.backoff.reset_all();
        cleared
    }
}
