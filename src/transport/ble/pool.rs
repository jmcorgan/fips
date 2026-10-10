//! BLE connection pool.
//!
//! BLE hardware limits concurrent connections (typically 4-10). The pool
//! enforces a configurable maximum. A link counts as a node's only while the
//! node's active peer for that node uses it; until then it is unverified.
//! When the pool is full, a newcomer evicts an unverified link that has had
//! `verify_grace` to complete its handshake, preferring a node's duplicate
//! links, oldest first; verified links are never evicted, and when no link is
//! evictable the newcomer is refused.

use std::collections::HashMap;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::identity::NodeAddr;
use crate::transport::TransportAddr;

use super::addr::BleAddr;

/// A single BLE connection in the pool.
pub struct BleConnection<S> {
    /// The L2CAP stream for this connection.
    pub stream: S,
    /// Background receive task handle.
    pub recv_task: Option<JoinHandle<()>>,
    /// Negotiated L2CAP send MTU.
    pub send_mtu: u16,
    /// Negotiated L2CAP receive MTU.
    pub recv_mtu: u16,
    /// When the connection was established.
    pub established_at: tokio::time::Instant,
    /// Whether the node's active peer for [`Self::node_addr`] uses this link.
    ///
    /// Set only by [`ConnectionPool::mark_verified`], when the node reports
    /// that its active peer for the link's claimed key now uses this link: a
    /// FIPS handshake this node initiated completed on it, or an authenticated
    /// frame from that peer arrived on it. Cleared when the node reports that
    /// the peer left the link, or when another link takes it over. The
    /// pre-handshake key exchange is a claim anyone in radio range can make,
    /// and proves nothing. Only a verified link blocks another link to the
    /// same node, names that node's address in announcements, or is
    /// protected from eviction.
    pub verified: bool,
    /// When this link's protection from eviction began: its admission, or the
    /// last time its peer was removed while on it. `established_at` stays the
    /// link's age.
    pub grace_from: tokio::time::Instant,
    /// Parsed remote address.
    pub addr: BleAddr,
    /// The peer's node address, once the pubkey exchange has learned it.
    ///
    /// The pool is keyed by *link* address, but a BLE link address is not a
    /// stable identity: peers using resolvable private addresses rotate theirs
    /// continually, and each rotation looks like a brand-new device. This
    /// field carries the identity the remote claimed, which does not rotate,
    /// so [`ConnectionPool::find_verified`] can recognise a peer already
    /// connected under an address never seen before, once the claim is
    /// verified. `None` for a connection whose peer is not yet identified.
    pub node_addr: Option<NodeAddr>,
}

impl<S> BleConnection<S> {
    /// Effective MTU for this connection: min(send, recv).
    pub fn effective_mtu(&self) -> u16 {
        self.send_mtu.min(self.recv_mtu)
    }
}

impl<S> Drop for BleConnection<S> {
    fn drop(&mut self) {
        if let Some(task) = self.recv_task.take() {
            task.abort();
        }
    }
}

/// The outcome of [`ConnectionPool::mark_verified`].
#[derive(Debug, PartialEq, Eq)]
pub enum Verify {
    /// The link is now the node's verified link; `demoted` lists the links
    /// that were verified for the same node and no longer are.
    Marked { demoted: Vec<TransportAddr> },
    /// The link claimed a different node than the one that authenticated on
    /// it, and stays unverified.
    Mismatch,
    /// No link is pooled at the address.
    Absent,
}

/// How long the pool must go without refusing a link before the next refusal
/// is reported again, so a flood logs at most one warning a minute.
const BOUND_LOG_HOLD: Duration = Duration::from_secs(60);

/// The outcome of offering a link to the pool. A refusal is an expected
/// state when the pool is full, not an error.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub enum Insert {
    /// Pooled. `evicted` names the unverified link removed to make room.
    /// `ended` carries the count of a refusal run this admission closed.
    Admitted {
        evicted: Option<TransportAddr>,
        ended: Option<u64>,
    },
    /// The pool is full and nothing in it may be evicted. `first` is set on
    /// the first refusal of a run, which the caller reports once. `ended`
    /// carries the count of an earlier run this refusal closed.
    Refused { first: bool, ended: Option<u64> },
}

/// Connection pool managing BLE connections.
pub struct ConnectionPool<S> {
    connections: HashMap<TransportAddr, BleConnection<S>>,
    max_connections: usize,
    /// How long a newly admitted link, or one whose peer has just left it, is
    /// protected from eviction so its handshake can complete. An honest
    /// handshake on a new link completes within a connect timeout when the
    /// node starts it at once; there is no measured basis beyond that. It
    /// protects honest links already admitted; it does not let an honest
    /// newcomer win a slot from an attacker who times its own replacements.
    verify_grace: Duration,
    /// Refusals in the current run, not yet reported as ended.
    refusals: u64,
    /// When the pool last refused a link.
    last_refusal: Option<tokio::time::Instant>,
}

impl<S> ConnectionPool<S> {
    /// Create a new pool with the given maximum capacity, protecting each new
    /// link from eviction for `verify_grace`.
    pub fn new(max_connections: usize, verify_grace: Duration) -> Self {
        Self {
            connections: HashMap::new(),
            max_connections,
            verify_grace,
            refusals: 0,
            last_refusal: None,
        }
    }

    /// Get the number of active connections.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Check if the pool is at capacity.
    pub fn is_full(&self) -> bool {
        self.connections.len() >= self.max_connections
    }

    /// Get the maximum pool capacity.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Look up a connection by transport address.
    pub fn get(&self, addr: &TransportAddr) -> Option<&BleConnection<S>> {
        self.connections.get(addr)
    }

    /// Look up a mutable connection by transport address.
    pub fn get_mut(&mut self, addr: &TransportAddr) -> Option<&mut BleConnection<S>> {
        self.connections.get_mut(addr)
    }

    /// Check if a connection exists for the given address.
    pub fn contains(&self, addr: &TransportAddr) -> bool {
        self.connections.contains_key(addr)
    }

    /// The address of the verified link to `node`, whatever link address it
    /// arrived on.
    ///
    /// This is the identity check [`Self::contains`] cannot make. A peer using
    /// resolvable private addresses presents a different link address every
    /// rotation, so an address-keyed lookup reports "not connected" for a peer
    /// that is very much connected, and the caller then opens a second link
    /// to it, and a third. Callers that know the peer's node address ask this
    /// before admitting a connection.
    ///
    /// Only a verified link is matched. A link whose claim is unverified does
    /// not count as the node's: anyone in radio range can claim any key, and
    /// letting that claim decline the node's own links would hand a stranger
    /// a block on them.
    pub fn find_verified(&self, node: &NodeAddr) -> Option<TransportAddr> {
        self.connections
            .iter()
            .find(|(_, c)| c.verified && c.node_addr.as_ref() == Some(node))
            .map(|(addr, _)| addr.clone())
    }

    /// The live link address of the verified link to `node`.
    ///
    /// [`Self::find_verified`] answers with the pool key; this answers with
    /// the `BleAddr` the link is actually on, which is what a caller needs
    /// when it has to *name* the peer's current address rather than merely
    /// test for one.
    pub fn verified_addr(&self, node: &NodeAddr) -> Option<BleAddr> {
        self.connections
            .values()
            .find(|c| c.verified && c.node_addr.as_ref() == Some(node))
            .map(|c| c.addr.clone())
    }

    /// Whether any link, verified or not, claims `node`.
    pub fn claims(&self, node: &NodeAddr) -> bool {
        self.connections
            .values()
            .any(|c| c.node_addr.as_ref() == Some(node))
    }

    /// Record that the node's active peer `node` now uses the link at `addr`.
    ///
    /// The link becomes `node`'s verified link and any other verified link
    /// claiming `node` is demoted. Nothing is removed or closed: the two ends
    /// of a pair can briefly send over different links, and each end marks
    /// the link its peer's frames arrive on, so closing the others here could
    /// close the link the other end is sending over. Demoted and unverified
    /// links leave by eviction or link loss.
    ///
    /// A link that claimed a different key than the one that authenticated on
    /// it is left unverified. A link with no claim, which only a transport
    /// without a local key produces, adopts `node`.
    pub fn mark_verified(&mut self, addr: &TransportAddr, node: &NodeAddr) -> Verify {
        match self.connections.get_mut(addr) {
            None => return Verify::Absent,
            Some(c) => match c.node_addr {
                Some(claimed) if &claimed != node => return Verify::Mismatch,
                _ => {
                    c.node_addr = Some(*node);
                    c.verified = true;
                }
            },
        }
        let mut demoted = Vec::new();
        for (other, c) in self.connections.iter_mut() {
            if other != addr && c.verified && c.node_addr.as_ref() == Some(node) {
                c.verified = false;
                demoted.push(other.clone());
            }
        }
        Verify::Marked { demoted }
    }

    /// Record that the node's active peer `node` no longer uses the link at
    /// `addr`. True when the link was verified for `node` and is no longer.
    ///
    /// The link stays pooled. With `regrace`, given when the peer itself was
    /// removed, its eviction grace starts again from that instant, the same
    /// grace a new link gets: a peer that restarts its session over the same
    /// link is withdrawn here and marked again only when its first
    /// authenticated frame arrives, and the link must not be evicted in
    /// between. Without it, as when the peer moved to another link, the grace
    /// is left alone, as a demotion leaves it: restarting it there would let
    /// one peer keep all its links protected by moving its frames among them.
    /// `established_at` is left alone either way; it stays the link's age.
    pub fn clear_verified(
        &mut self,
        addr: &TransportAddr,
        node: &NodeAddr,
        regrace: Option<tokio::time::Instant>,
    ) -> bool {
        match self.connections.get_mut(addr) {
            Some(c) if c.verified && c.node_addr.as_ref() == Some(node) => {
                c.verified = false;
                if let Some(now) = regrace {
                    c.grace_from = now;
                }
                true
            }
            _ => false,
        }
    }

    /// Offer a link to the pool at `now`.
    ///
    /// A link at an address already pooled replaces it. Otherwise it is
    /// admitted while there is room; when the pool is full it evicts an
    /// unverified link past its grace, and is refused when there is none.
    pub fn insert(
        &mut self,
        addr: TransportAddr,
        conn: BleConnection<S>,
        now: tokio::time::Instant,
    ) -> Insert {
        if self.connections.contains_key(&addr) || !self.is_full() {
            self.connections.insert(addr, conn);
            let ended = self.note_admission(now);
            return Insert::Admitted {
                evicted: None,
                ended,
            };
        }
        match self.victim(now) {
            Some(victim) => {
                self.connections.remove(&victim);
                self.connections.insert(addr, conn);
                let ended = self.note_admission(now);
                Insert::Admitted {
                    evicted: Some(victim),
                    ended,
                }
            }
            None => self.note_refusal(now),
        }
    }

    /// Remove a connection by address.
    pub fn remove(&mut self, addr: &TransportAddr) -> Option<BleConnection<S>> {
        self.connections.remove(addr)
    }

    /// Get all connection addresses.
    pub fn addrs(&self) -> Vec<TransportAddr> {
        self.connections.keys().cloned().collect()
    }

    /// The link a newcomer to a full pool may evict, if any.
    ///
    /// Only an unverified link that has had its grace may go. A node's
    /// duplicate links go first, so that one neighbour's address rotations
    /// displace only its own older links rather than another neighbour's only
    /// one; then the oldest. The grace is read from `grace_from` and the age
    /// from `established_at`, so a link whose peer left it is protected for
    /// one grace and then ranks by its real age.
    fn victim(&self, now: tokio::time::Instant) -> Option<TransportAddr> {
        let evictable = |c: &BleConnection<S>| {
            !c.verified && now.saturating_duration_since(c.grace_from) >= self.verify_grace
        };
        let duplicated = |c: &BleConnection<S>| {
            c.node_addr.is_some_and(|node| {
                self.connections
                    .values()
                    .filter(|other| other.node_addr == Some(node))
                    .count()
                    > 1
            })
        };
        let oldest = |dup_only: bool| {
            self.connections
                .iter()
                .filter(|(_, c)| evictable(c) && (!dup_only || duplicated(c)))
                .min_by_key(|(_, c)| c.established_at)
                .map(|(addr, _)| addr.clone())
        };
        oldest(true).or_else(|| oldest(false))
    }

    /// Count a refusal at `now`. A refusal after a quiet `BOUND_LOG_HOLD`
    /// starts a new run, closing any earlier one that was never reported.
    fn note_refusal(&mut self, now: tokio::time::Instant) -> Insert {
        let first = self
            .last_refusal
            .is_none_or(|last| now.saturating_duration_since(last) >= BOUND_LOG_HOLD);
        let ended = if first && self.refusals > 0 {
            Some(std::mem::take(&mut self.refusals))
        } else {
            None
        };
        self.refusals += 1;
        self.last_refusal = Some(now);
        Insert::Refused { first, ended }
    }

    /// Close a refusal run that has been quiet for `BOUND_LOG_HOLD`, returning
    /// its count for the caller to report.
    fn note_admission(&mut self, now: tokio::time::Instant) -> Option<u64> {
        let last = self.last_refusal?;
        if now.saturating_duration_since(last) < BOUND_LOG_HOLD {
            return None;
        }
        self.last_refusal = None;
        Some(std::mem::take(&mut self.refusals))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(n: u8) -> TransportAddr {
        TransportAddr::from_string(&format!("hci0/AA:BB:CC:DD:EE:{n:02X}"))
    }

    fn test_ble_addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: "hci0".to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
        }
    }

    /// A distinct node identity per `n` — the identity that does NOT rotate.
    fn test_node(n: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        NodeAddr::from_bytes(bytes)
    }

    fn test_conn(n: u8) -> BleConnection<()> {
        BleConnection {
            stream: (),
            recv_task: None,
            send_mtu: 2048,
            recv_mtu: 2048,
            established_at: tokio::time::Instant::now(),
            verified: false,
            grace_from: tokio::time::Instant::now(),
            addr: test_ble_addr(n),
            node_addr: None,
        }
    }

    /// A link at `test_addr(n)` claiming `test_node(node)`, admitted at `at`.
    fn claimed(n: u8, node: u8, verified: bool, at: tokio::time::Instant) -> BleConnection<()> {
        let mut conn = test_conn(n);
        conn.node_addr = Some(test_node(node));
        conn.verified = verified;
        conn.established_at = at;
        conn.grace_from = at;
        conn
    }

    /// The insertion instant for tests that do not depend on time.
    fn now() -> tokio::time::Instant {
        tokio::time::Instant::now()
    }

    /// The grace every pool test runs with.
    const GRACE: std::time::Duration = std::time::Duration::from_secs(10);

    #[test]
    fn test_pool_basic_insert() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        assert!(pool.is_empty());

        assert!(matches!(
            pool.insert(test_addr(1), test_conn(1), now()),
            Insert::Admitted { .. }
        ));
        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());
        assert!(pool.contains(&test_addr(1)));
    }

    #[test]
    fn test_pool_remove() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        assert!(matches!(
            pool.insert(test_addr(1), test_conn(1), now()),
            Insert::Admitted { .. }
        ));
        assert!(pool.remove(&test_addr(1)).is_some());
        assert!(pool.is_empty());
    }

    /// A full pool evicts its oldest unverified link once that link has had
    /// its grace, never an older verified one.
    #[test]
    fn a_full_pool_evicts_its_oldest_unverified_link_once_past_its_grace() {
        let t0 = now();
        let secs = Duration::from_secs;
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        for n in 1..=5 {
            let _ = pool.insert(test_addr(n), claimed(n, n, true, t0), t0);
        }
        let _ = pool.insert(
            test_addr(6),
            claimed(6, 6, false, t0 + secs(1)),
            t0 + secs(1),
        );
        let _ = pool.insert(
            test_addr(7),
            claimed(7, 7, false, t0 + secs(2)),
            t0 + secs(2),
        );
        assert!(pool.is_full());

        let at = t0 + secs(20);
        assert_eq!(
            pool.insert(test_addr(8), claimed(8, 8, false, at), at),
            Insert::Admitted {
                evicted: Some(test_addr(6)),
                ended: None
            }
        );
        assert_eq!(pool.len(), 7);
        assert!(pool.contains(&test_addr(8)));
    }

    /// Replacing the link at an address already pooled does not grow the
    /// pool, and the replacement starts unverified.
    #[test]
    fn test_pool_replace_existing() {
        let t0 = now();
        let mut pool: ConnectionPool<()> = ConnectionPool::new(2, GRACE);
        let _ = pool.insert(test_addr(1), claimed(1, 1, true, t0), t0);

        let result = pool.insert(test_addr(1), test_conn(1), t0);
        assert!(matches!(result, Insert::Admitted { evicted: None, .. }));
        assert_eq!(pool.len(), 1);
        assert!(!pool.get(&test_addr(1)).unwrap().verified);
    }

    #[test]
    fn test_pool_effective_mtu() {
        let mut conn = test_conn(1);
        conn.send_mtu = 1024;
        conn.recv_mtu = 2048;
        assert_eq!(conn.effective_mtu(), 1024);
    }

    #[test]
    fn test_pool_addrs() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        assert!(matches!(
            pool.insert(test_addr(1), test_conn(1), now()),
            Insert::Admitted { .. }
        ));
        assert!(matches!(
            pool.insert(test_addr(2), test_conn(2), now()),
            Insert::Admitted { .. }
        ));

        let mut addrs = pool.addrs();
        addrs.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        assert_eq!(addrs.len(), 2);
    }

    /// A verified link's node address is found regardless of which link
    /// address it arrived on: the whole point of the lookup, since the link
    /// address rotates.
    #[test]
    fn test_find_verified_matches_across_a_rotated_link_address() {
        let t0 = now();
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        let _ = pool.insert(test_addr(1), claimed(1, 1, true, t0), t0);

        // Found under the address it was inserted with...
        assert_eq!(pool.find_verified(&test_node(1)), Some(test_addr(1)));
        assert!(pool.contains(&test_addr(1)));
        // ...and a rotated address for the same peer is NOT found by
        // `contains`, which is exactly the gap `find_verified` closes.
        assert!(!pool.contains(&test_addr(99)));
        assert_eq!(pool.find_verified(&test_node(1)), Some(test_addr(1)));
    }

    #[test]
    fn test_find_verified_ignores_unidentified_connections() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        // No pubkey exchange yet, so no node address.
        assert!(matches!(
            pool.insert(test_addr(1), test_conn(1), now()),
            Insert::Admitted { .. }
        ));
        assert_eq!(pool.find_verified(&test_node(1)), None);
    }

    /// A claim is not a verified link: anyone in radio range can make one.
    #[test]
    fn find_verified_ignores_an_unverified_claim() {
        let t0 = now();
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        let _ = pool.insert(test_addr(1), claimed(1, 1, false, t0), t0);
        assert_eq!(pool.find_verified(&test_node(1)), None);
        assert_eq!(pool.verified_addr(&test_node(1)), None);
        assert!(pool.claims(&test_node(1)), "the claim itself is visible");
    }

    #[test]
    fn test_find_verified_returns_none_for_an_unconnected_node() {
        let t0 = now();
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        let _ = pool.insert(test_addr(1), claimed(1, 1, true, t0), t0);
        assert_eq!(pool.find_verified(&test_node(2)), None);
    }

    /// Distinct nodes do not alias: each resolves to its own link address.
    #[test]
    fn test_find_verified_distinguishes_two_nodes() {
        let t0 = now();
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        let _ = pool.insert(test_addr(1), claimed(1, 1, true, t0), t0);
        let _ = pool.insert(test_addr(2), claimed(2, 2, true, t0), t0);

        assert_eq!(pool.find_verified(&test_node(1)), Some(test_addr(1)));
        assert_eq!(pool.find_verified(&test_node(2)), Some(test_addr(2)));
    }

    /// The live link address is reported for a peer found under any of its
    /// rotated aliases: what a caller needs when it has to name the peer's
    /// current address rather than merely test for one.
    #[test]
    fn test_verified_addr_reports_the_incumbent_not_the_alias() {
        let t0 = now();
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        let _ = pool.insert(test_addr(1), claimed(1, 1, true, t0), t0);

        assert_eq!(pool.verified_addr(&test_node(1)), Some(test_ble_addr(1)));
        assert!(!pool.contains(&test_addr(99)));
        // An unconnected node has no incumbent, so the caller keeps whatever
        // address it observed.
        assert_eq!(pool.verified_addr(&test_node(2)), None);
    }

    #[test]
    fn test_verified_addr_ignores_unidentified_connections() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        assert!(matches!(
            pool.insert(test_addr(1), test_conn(1), now()),
            Insert::Admitted { .. }
        ));
        assert_eq!(pool.verified_addr(&test_node(1)), None);
    }

    /// The regression this guards: without a node-identity check, N rotated
    /// addresses for ONE peer become N pool entries and evict real peers.
    /// With it, the caller sees the verified peer is already present and
    /// declines.
    #[test]
    fn test_rotated_addresses_would_otherwise_fill_the_pool() {
        let t0 = now();
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        let node = test_node(1);
        let _ = pool.insert(test_addr(1), claimed(1, 1, true, t0), t0);

        // Ten rotations arrive. Each is a distinct link address, so `contains`
        // says "new" every time, but `find_verified` recognises all of them.
        for n in 2..12u8 {
            assert!(
                !pool.contains(&test_addr(n)),
                "rotation {n} looks new by address"
            );
            assert_eq!(
                pool.find_verified(&node),
                Some(test_addr(1)),
                "rotation {n} is recognised as the peer already connected",
            );
        }
        // Nothing was admitted, so the pool still holds exactly one link, and
        // it is the incumbent: the first one, not the newest.
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&test_addr(1)));
    }

    /// A link that claimed one key and authenticated as another verifies
    /// nothing, and leaves the other node's link alone.
    #[test]
    fn mark_verified_ignores_a_link_that_claimed_another_node() {
        let t0 = now();
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        let _ = pool.insert(test_addr(1), claimed(1, 1, false, t0), t0);
        let _ = pool.insert(test_addr(2), claimed(2, 2, false, t0), t0);

        assert_eq!(
            pool.mark_verified(&test_addr(1), &test_node(2)),
            Verify::Mismatch
        );
        assert!(!pool.get(&test_addr(1)).unwrap().verified);
        assert_eq!(
            pool.get(&test_addr(1)).unwrap().node_addr,
            Some(test_node(1))
        );
        assert!(!pool.get(&test_addr(2)).unwrap().verified);
        assert_eq!(
            pool.mark_verified(&test_addr(9), &test_node(1)),
            Verify::Absent
        );
    }

    /// Verifying a second link for a node demotes the first and closes
    /// nothing.
    #[test]
    fn a_second_verification_demotes_the_first_link_and_leaves_it_pooled() {
        let t0 = now();
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        let _ = pool.insert(test_addr(1), claimed(1, 1, false, t0), t0);
        let _ = pool.insert(test_addr(2), claimed(2, 1, false, t0), t0);

        assert_eq!(
            pool.mark_verified(&test_addr(1), &test_node(1)),
            Verify::Marked { demoted: vec![] }
        );
        assert_eq!(
            pool.mark_verified(&test_addr(2), &test_node(1)),
            Verify::Marked {
                demoted: vec![test_addr(1)]
            }
        );
        assert_eq!(pool.len(), 2);
        assert!(!pool.get(&test_addr(1)).unwrap().verified);
        assert!(pool.get(&test_addr(2)).unwrap().verified);
        // Marking the verified link again changes nothing.
        assert_eq!(
            pool.mark_verified(&test_addr(2), &test_node(1)),
            Verify::Marked { demoted: vec![] }
        );

        // With the pool full and past the grace, the demoted link is the
        // first to go.
        for n in 3..=7 {
            let _ = pool.insert(test_addr(n), claimed(n, n, true, t0), t0);
        }
        let at = t0 + Duration::from_secs(20);
        assert_eq!(
            pool.insert(test_addr(8), claimed(8, 8, false, at), at),
            Insert::Admitted {
                evicted: Some(test_addr(1)),
                ended: None
            }
        );
    }

    /// A full pool of links carrying sessions refuses a newcomer rather than
    /// evicting one of them, however old they are.
    #[test]
    fn a_full_pool_of_verified_links_refuses_an_unverified_newcomer() {
        let t0 = tokio::time::Instant::now();
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        for n in 1..=7 {
            let _ = pool.insert(test_addr(n), claimed(n, n, true, t0), t0);
        }
        let later = t0 + std::time::Duration::from_secs(60);
        let _ = pool.insert(test_addr(8), claimed(8, 8, false, later), later);
        assert_eq!(pool.len(), 7);
        for n in 1..=7 {
            assert!(pool.contains(&test_addr(n)), "verified link {n} is kept");
        }
        assert!(!pool.contains(&test_addr(8)), "the newcomer is refused");
    }

    /// A newly admitted link has its grace to complete a handshake: newcomers
    /// to a full pool are refused rather than evicting it.
    #[test]
    fn a_newly_admitted_unverified_link_is_not_evicted_before_its_grace() {
        let t0 = now();
        let secs = Duration::from_secs;
        let grace = GRACE;
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, grace);
        for n in 1..=6 {
            let _ = pool.insert(test_addr(n), claimed(n, n, true, t0), t0);
        }
        let t = t0 + secs(100);
        let _ = pool.insert(test_addr(7), claimed(7, 7, false, t), t);

        let at = t + secs(1);
        assert_eq!(
            pool.insert(test_addr(8), claimed(8, 8, false, at), at),
            Insert::Refused {
                first: true,
                ended: None
            }
        );
        let at = t + secs(2);
        assert_eq!(
            pool.insert(test_addr(9), claimed(9, 9, false, at), at),
            Insert::Refused {
                first: false,
                ended: None
            }
        );
        assert!(
            pool.contains(&test_addr(7)),
            "the honest link keeps its slot"
        );
        assert!(matches!(
            pool.mark_verified(&test_addr(7), &test_node(7)),
            Verify::Marked { .. }
        ));
    }

    /// A run of refusals is reported once, and closed with its count once the
    /// pool has gone a minute without refusing.
    #[test]
    fn a_refusal_run_is_reported_once_and_cleared_after_a_quiet_minute() {
        let t0 = now();
        let secs = Duration::from_secs;
        let refused = |first, ended| Insert::Refused { first, ended };
        let mut pool: ConnectionPool<()> = ConnectionPool::new(1, GRACE);
        let _ = pool.insert(test_addr(1), claimed(1, 1, true, t0), t0);
        for (k, first) in [(0, true), (10, false), (20, false)] {
            let at = t0 + secs(k);
            assert_eq!(
                pool.insert(test_addr(2), claimed(2, 2, false, at), at),
                refused(first, None)
            );
        }
        let last = t0 + secs(20);

        // Room made, then an admission inside the minute: the run stays open.
        pool.remove(&test_addr(1));
        let at = last + secs(30);
        assert_eq!(
            pool.insert(test_addr(3), claimed(3, 3, false, at), at),
            Insert::Admitted {
                evicted: None,
                ended: None
            }
        );
        // An admission a minute after the last refusal closes it.
        pool.remove(&test_addr(3));
        let at = last + secs(61);
        assert_eq!(
            pool.insert(test_addr(4), claimed(4, 4, false, at), at),
            Insert::Admitted {
                evicted: None,
                ended: Some(3)
            }
        );
        let _ = pool.mark_verified(&test_addr(4), &test_node(4));
        let at = last + secs(62);
        assert_eq!(
            pool.insert(test_addr(5), claimed(5, 5, false, at), at),
            refused(true, None),
            "the next refusal starts a new run"
        );

        // A run that ends with no insert is reported by the next refusal.
        let mut pool: ConnectionPool<()> = ConnectionPool::new(1, GRACE);
        let _ = pool.insert(test_addr(1), claimed(1, 1, true, t0), t0);
        for k in [0, 1] {
            let at = t0 + secs(k);
            let _ = pool.insert(test_addr(2), claimed(2, 2, false, at), at);
        }
        let at = t0 + secs(91);
        assert_eq!(
            pool.insert(test_addr(2), claimed(2, 2, false, at), at),
            refused(true, Some(2))
        );
    }

    /// A node's duplicate link goes before another node's only link, even an
    /// older one.
    #[test]
    fn a_full_pool_evicts_a_nodes_duplicate_before_another_nodes_only_link() {
        let t0 = now();
        let secs = Duration::from_secs;
        let mut pool: ConnectionPool<()> = ConnectionPool::new(3, GRACE);
        // Node 3's only link, then two links claiming node 1.
        let _ = pool.insert(test_addr(1), claimed(1, 3, false, t0), t0);
        let _ = pool.insert(
            test_addr(2),
            claimed(2, 1, false, t0 + secs(1)),
            t0 + secs(1),
        );
        let _ = pool.insert(
            test_addr(3),
            claimed(3, 1, false, t0 + secs(2)),
            t0 + secs(2),
        );

        let at = t0 + secs(20);
        assert_eq!(
            pool.insert(test_addr(4), claimed(4, 4, false, at), at),
            Insert::Admitted {
                evicted: Some(test_addr(2)),
                ended: None
            },
            "node 1's older duplicate goes first"
        );
        let at = t0 + secs(21);
        assert_eq!(
            pool.insert(test_addr(5), claimed(5, 5, false, at), at),
            Insert::Admitted {
                evicted: Some(test_addr(1)),
                ended: None
            },
            "with no duplicate left, the oldest goes"
        );
    }

    /// A link its peer moved off keeps the grace it had: once that has passed
    /// it is evictable at once, so a peer moving its frames among its own
    /// links protects only the one it is on.
    #[test]
    fn a_link_its_peer_moved_off_keeps_the_grace_it_had() {
        let t0 = now();
        let secs = Duration::from_secs;
        let mut pool: ConnectionPool<()> = ConnectionPool::new(2, GRACE);
        let _ = pool.insert(test_addr(1), claimed(1, 1, true, t0), t0);
        let _ = pool.insert(test_addr(2), claimed(2, 1, false, t0), t0);

        let moved = t0 + secs(60);
        assert!(pool.clear_verified(&test_addr(1), &test_node(1), None));
        let _ = pool.mark_verified(&test_addr(2), &test_node(1));
        assert_eq!(
            pool.insert(test_addr(3), claimed(3, 3, false, moved), moved),
            Insert::Admitted {
                evicted: Some(test_addr(1)),
                ended: None
            },
            "the link the peer moved off is evicted without a new grace"
        );
    }

    /// A link whose peer left it gets the grace again, then ranks by its age.
    #[test]
    fn a_withdrawn_link_gets_the_grace_again() {
        let t0 = now();
        let secs = Duration::from_secs;
        let mut pool: ConnectionPool<()> = ConnectionPool::new(2, GRACE);
        let _ = pool.insert(test_addr(1), claimed(1, 1, true, t0), t0);
        let _ = pool.insert(
            test_addr(2),
            claimed(2, 2, false, t0 + secs(1)),
            t0 + secs(1),
        );

        assert!(pool.clear_verified(&test_addr(1), &test_node(1), Some(t0 + secs(60))));
        assert_eq!(pool.get(&test_addr(1)).unwrap().established_at, t0);

        let at = t0 + secs(61);
        assert_eq!(
            pool.insert(test_addr(3), claimed(3, 3, false, at), at),
            Insert::Admitted {
                evicted: Some(test_addr(2)),
                ended: None
            },
            "the withdrawn link is inside its new grace"
        );
        let at = t0 + secs(62);
        assert!(matches!(
            pool.insert(test_addr(4), claimed(4, 4, false, at), at),
            Insert::Refused { .. }
        ));
        let at = t0 + Duration::from_millis(70_500);
        assert_eq!(
            pool.insert(test_addr(5), claimed(5, 5, false, at), at),
            Insert::Admitted {
                evicted: Some(test_addr(1)),
                ended: None
            },
            "once past its new grace the withdrawn link goes"
        );
    }
}
