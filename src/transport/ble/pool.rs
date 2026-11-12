//! BLE connection pool.
//!
//! BLE hardware limits concurrent connections (typically 4-10). The pool
//! enforces a configurable maximum. An address counts as carrying a node's
//! session only while the node's active peer uses it; until then it is
//! unverified. When the pool is full, a newcomer evicts an unverified address
//! that has had `verify_grace` to complete its handshake, preferring a
//! node's duplicate addresses, oldest first; verified addresses are never
//! evicted, and when nothing is evictable the newcomer is refused.
//!
//! ## Two channels to one address
//!
//! Two nodes that dial each other at once each end up with two L2CAP
//! channels at the same address: the one it dialled and the one the peer
//! dialled. Before the XX handshake neither end has an input the other
//! shares that could pick one: direction is mirrored, and BLE addresses
//! rotate and are not always known to their owner. So the pool keeps a
//! short list of channels per address. The second one is *held* beside the
//! first until the handshake names the peer, and the node then *settles*
//! the address, telling the pool which direction to keep. Both ends
//! compute that from node order, so both keep the same channel.
//!
//! A channel the pool lets go on purpose is *retired*, not dropped: it
//! takes no new frames, its writer finishes what is already queued, and
//! its reader keeps delivering until the peer closes it or the driver's
//! linger ends. The decisions here are pure ([`admit`], [`settle`]); the
//! driver in `mod.rs` spawns the tasks and the linger timers.

use std::collections::HashMap;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::identity::NodeAddr;
use crate::transport::TransportAddr;

use super::addr::BleAddr;

/// How many frames may be queued for one BLE connection before sends to it
/// fail. Shallower than the IP transports': a BLE link carries a fraction of
/// their throughput, so a queue of the same depth would represent seconds of
/// backlog rather than a burst.
pub const SEND_QUEUE_DEPTH: usize = 16;

/// How many path messages may be queued for one BLE connection, apart from
/// its data, before sends of them fail: the number of probes a path keeps
/// outstanding. Bounded, so a connection that has stopped draining still
/// refuses its probes and the path still fails.
pub const PATH_QUEUE_DEPTH: usize = 8;

/// Most channels held at one address.
///
/// One side has at most two concurrent dials to an address (the scan
/// loop's probe and the node's own dial), and keeps at most one of them
/// (see [`admit`]), so a conforming peer leaves at most one outbound and
/// two inbound channels here.
pub const MAX_HELD: usize = 3;

/// A single BLE connection in the pool.
pub struct BleConnection<S> {
    /// The L2CAP stream for this connection.
    pub stream: S,
    /// Frames queued for the writer task. Sending is an enqueue, never a
    /// write: the write is awaited only by `send_task`, so no caller can be
    /// held by a peer that has stopped draining — and, on this transport in
    /// particular, no caller holds the pool lock while it happens.
    pub send_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Path messages queued for the writer task, which sends them before
    /// anything in [`Self::send_tx`], so a queue full of data neither
    /// refuses nor holds them back.
    pub path_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Writer task for this connection.
    pub send_task: Option<JoinHandle<()>>,
    /// Background receive task handle.
    pub recv_task: Option<JoinHandle<()>>,
    /// Negotiated L2CAP send MTU.
    pub send_mtu: u16,
    /// Negotiated L2CAP receive MTU.
    pub recv_mtu: u16,
    /// When the connection was established.
    pub established_at: tokio::time::Instant,
    /// Parsed remote address.
    pub addr: BleAddr,
    /// Whether this side dialled the channel.
    pub outbound: bool,
    /// Tells this channel apart from others at its address. The channel's
    /// own tasks remove it by `(address, id)`, so the end of one channel
    /// cannot take another at the same address with it.
    pub id: u64,
}

impl<S> BleConnection<S> {
    /// Effective MTU for this connection: min(send, recv).
    pub fn effective_mtu(&self) -> u16 {
        self.send_mtu.min(self.recv_mtu)
    }

    /// Stop the channel taking new frames.
    ///
    /// Swapping in senders whose receivers are already gone drops the only
    /// stored sender of each of the writer's queues, so the writer task
    /// writes every frame already queued and then ends. The receive task is
    /// untouched.
    fn retire(&mut self) {
        let (closed, _) = tokio::sync::mpsc::channel(1);
        self.send_tx = closed;
        let (closed, _) = tokio::sync::mpsc::channel(1);
        self.path_tx = closed;
    }
}

impl<S> Drop for BleConnection<S> {
    fn drop(&mut self) {
        if let Some(task) = self.recv_task.take() {
            task.abort();
        }
        if let Some(task) = self.send_task.take() {
            task.abort();
        }
    }
}

/// What the pool does with a channel offered at an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The address had no channel: this one is its link.
    Admit,
    /// Kept beside the channels already held, until the address is settled.
    Hold,
    /// Kept, and every channel already held is retired.
    Replace,
    /// Retired on arrival.
    Retire,
}

/// Decide what to do with a channel offered at an address.
///
/// `held_out` and `held_in` count the channels already held there by
/// direction, `verdict` is the direction a settlement chose to keep, if
/// one has, and `outbound` is the newcomer's direction. The rules, first
/// match wins:
///
/// 1. Nothing held: admit. A lone link is always admitted, whichever side
///    dialled it.
/// 2. [`MAX_HELD`] channels held: retire the newcomer.
/// 3. An outbound newcomer where an outbound is held: retire the newcomer.
///    This side dialled twice, so it alone decides; the peer holds both as
///    inbound and follows when it reads end-of-stream.
/// 4. An inbound newcomer where an inbound is held: hold it. The peer
///    dialled twice and decides by rule 3; this side never retires one of
///    these itself. If both sides decided they could pick different
///    channels, and if neither did both would stay for the life of the
///    link.
/// 5. Otherwise the newcomer is opposite in direction to every held
///    channel. With no verdict, hold it; with a verdict for its direction,
///    replace the held channels with it; with a verdict against it, retire
///    it.
pub fn admit(held_out: usize, held_in: usize, verdict: Option<bool>, outbound: bool) -> Admission {
    if held_out + held_in == 0 {
        return Admission::Admit;
    }
    if held_out + held_in >= MAX_HELD {
        return Admission::Retire;
    }
    if outbound && held_out > 0 {
        return Admission::Retire;
    }
    if !outbound && held_in > 0 {
        return Admission::Hold;
    }
    match verdict {
        None => Admission::Hold,
        Some(keep_outbound) if keep_outbound == outbound => Admission::Replace,
        Some(_) => Admission::Retire,
    }
}

/// Decide which held channels a settlement retires.
///
/// `held` lists each held channel's `(id, outbound)`. If a channel of the
/// kept direction is held, every channel of the other direction goes.
/// Otherwise none does: the verdict waits for the winning channel to
/// arrive, so a side never retires its only link.
pub fn settle(held: &[(u64, bool)], keep_outbound: bool) -> Vec<u64> {
    if !held.iter().any(|&(_, outbound)| outbound == keep_outbound) {
        return Vec::new();
    }
    held.iter()
        .filter(|&&(_, outbound)| outbound != keep_outbound)
        .map(|&(id, _)| id)
        .collect()
}

/// The outcome of offering a channel to the pool.
#[derive(Debug, PartialEq, Eq)]
pub struct Admitted {
    /// What happened to the channel offered.
    pub admission: Admission,
    /// An unverified address evicted to make room, if one was.
    pub evicted: Option<TransportAddr>,
    /// Ids of the channels at this address the offer retired, the newcomer
    /// included when it was itself retired.
    pub retired: Vec<u64>,
    /// The count of a refusal run this offer closed, for the caller to
    /// report.
    pub ended: Option<u64>,
}

/// A channel the pool refused: it is full and nothing in it may be evicted.
/// An expected state when the pool is full, not an error.
#[derive(Debug, PartialEq, Eq)]
pub struct Refused {
    /// Set on the first refusal of a run, which the caller reports once.
    pub first: bool,
    /// The count of an earlier run this refusal closed.
    pub ended: Option<u64>,
}

/// The outcome of [`ConnectionPool::mark_verified`].
#[derive(Debug, PartialEq, Eq)]
pub enum Verify {
    /// The address is now the node's verified address; `demoted` lists the
    /// addresses that were verified for the same node and no longer are.
    Marked { demoted: Vec<TransportAddr> },
    /// No channel is held at the address.
    Absent,
}

/// How long the pool must go without refusing a channel before the next
/// refusal is reported again, so a flood logs at most one warning a minute.
const BOUND_LOG_HOLD: Duration = Duration::from_secs(60);

/// The channels at one address.
struct Slot<S> {
    /// Held channels, oldest first. Sends use the first. Never empty: the
    /// slot goes when its last held channel does.
    held: Vec<BleConnection<S>>,
    /// The direction a settlement chose to keep, once one has.
    verdict: Option<bool>,
    /// Whether the node's active peer for [`Self::node`] uses this address.
    ///
    /// Set only by [`ConnectionPool::mark_verified`], when the node reports
    /// that its active peer now uses the address: a FIPS handshake this node
    /// initiated completed on it, or an authenticated frame from that peer
    /// arrived on it. Cleared when the node reports that the peer left the
    /// address, or when another address takes it over. Only a verified
    /// address is protected from eviction.
    verified: bool,
    /// The node whose active peer was last verified here, if any. Never set
    /// from anything the remote says before a handshake.
    node: Option<NodeAddr>,
    /// When this address's protection from eviction began: its admission,
    /// or the last time its peer was removed while on it. The age of its
    /// first held channel stays the address's age.
    grace_from: tokio::time::Instant,
}

/// Connection pool managing BLE connections.
///
/// Capacity counts addresses, not channels: the extra channels held during
/// a race, and the retiring ones, are the same device on the same link.
pub struct ConnectionPool<S> {
    slots: HashMap<TransportAddr, Slot<S>>,
    /// Retired channels still writing out their queue or lingering for the
    /// peer's last frames.
    retiring: Vec<(TransportAddr, BleConnection<S>)>,
    max_connections: usize,
    /// How long a newly admitted address, or one whose peer has just left
    /// it, is protected from eviction so its handshake can complete. An
    /// honest handshake on a new link completes within a connect timeout
    /// when the node starts it at once; there is no measured basis beyond
    /// that. It protects honest links already admitted; it does not let an
    /// honest newcomer win a slot from an attacker who times its own
    /// replacements.
    verify_grace: Duration,
    /// Refusals in the current run, not yet reported as ended.
    refusals: u64,
    /// When the pool last refused a channel.
    last_refusal: Option<tokio::time::Instant>,
}

impl<S> ConnectionPool<S> {
    /// Create a new pool with the given maximum capacity, protecting each new
    /// address from eviction for `verify_grace`.
    pub fn new(max_connections: usize, verify_grace: Duration) -> Self {
        Self {
            slots: HashMap::new(),
            retiring: Vec::new(),
            max_connections,
            verify_grace,
            refusals: 0,
            last_refusal: None,
        }
    }

    /// Get the number of linked addresses.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Check if the pool is at capacity.
    pub fn is_full(&self) -> bool {
        self.slots.len() >= self.max_connections
    }

    /// Get the maximum pool capacity.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// The channel sends to `addr` use: the oldest held there.
    pub fn get(&self, addr: &TransportAddr) -> Option<&BleConnection<S>> {
        self.slots.get(addr).and_then(|slot| slot.held.first())
    }

    /// Check if a connection exists for the given address.
    pub fn contains(&self, addr: &TransportAddr) -> bool {
        self.slots.contains_key(addr)
    }

    /// `(id, outbound)` of each channel held at `addr`, oldest first.
    pub fn held(&self, addr: &TransportAddr) -> Vec<(u64, bool)> {
        self.slots
            .get(addr)
            .map(|slot| slot.held.iter().map(|c| (c.id, c.outbound)).collect())
            .unwrap_or_default()
    }

    /// Ids of the channels retiring at `addr`.
    pub fn retiring(&self, addr: &TransportAddr) -> Vec<u64> {
        self.retiring
            .iter()
            .filter(|(a, _)| a == addr)
            .map(|(_, c)| c.id)
            .collect()
    }

    /// Offer a channel at `addr` at `now`. A new address is admitted while
    /// there is room; when the pool is full it evicts an unverified address
    /// past its grace.
    ///
    /// Returns `Err` if the pool is full and nothing can be evicted; the
    /// channel is then dropped.
    pub fn insert(
        &mut self,
        addr: TransportAddr,
        mut conn: BleConnection<S>,
        now: tokio::time::Instant,
    ) -> Result<Admitted, Refused> {
        let (held_out, held_in, verdict) = match self.slots.get(&addr) {
            Some(slot) => {
                let held_out = slot.held.iter().filter(|c| c.outbound).count();
                (held_out, slot.held.len() - held_out, slot.verdict)
            }
            None => (0, 0, None),
        };
        let admission = admit(held_out, held_in, verdict, conn.outbound);
        let mut evicted = None;
        let mut retired = Vec::new();
        match admission {
            Admission::Admit => {
                if self.is_full() {
                    let Some(victim) = self.victim(now) else {
                        return Err(self.note_refusal(now));
                    };
                    self.remove(&victim);
                    evicted = Some(victim);
                }
                self.slots.insert(
                    addr,
                    Slot {
                        held: vec![conn],
                        verdict: None,
                        verified: false,
                        node: None,
                        grace_from: now,
                    },
                );
            }
            Admission::Hold => {
                if let Some(slot) = self.slots.get_mut(&addr) {
                    slot.held.push(conn);
                }
            }
            Admission::Replace => {
                if let Some(slot) = self.slots.get_mut(&addr) {
                    for mut old in std::mem::replace(&mut slot.held, vec![conn]) {
                        old.retire();
                        retired.push(old.id);
                        self.retiring.push((addr.clone(), old));
                    }
                }
            }
            Admission::Retire => {
                conn.retire();
                retired.push(conn.id);
                self.retiring.push((addr, conn));
            }
        }
        let ended = self.note_admission(now);
        Ok(Admitted {
            admission,
            evicted,
            retired,
            ended,
        })
    }

    /// Record that the node's active peer `node` now uses the address
    /// `addr`.
    ///
    /// The address becomes `node`'s verified address and any other address
    /// verified for `node` is demoted. Nothing is removed or closed: the two
    /// ends of a pair can briefly send over different links, and each end
    /// marks the address its peer's frames arrive on, so closing the others
    /// here could close the link the other end is sending over. Demoted and
    /// unverified addresses leave by eviction or link loss.
    pub fn mark_verified(&mut self, addr: &TransportAddr, node: &NodeAddr) -> Verify {
        let Some(slot) = self.slots.get_mut(addr) else {
            return Verify::Absent;
        };
        slot.node = Some(*node);
        slot.verified = true;
        let mut demoted = Vec::new();
        for (other, slot) in self.slots.iter_mut() {
            if other != addr && slot.verified && slot.node.as_ref() == Some(node) {
                slot.verified = false;
                demoted.push(other.clone());
            }
        }
        Verify::Marked { demoted }
    }

    /// Record that the node's active peer `node` no longer uses the address
    /// `addr`. True when the address was verified for `node` and is no
    /// longer.
    ///
    /// The address stays pooled. With `regrace`, given when the peer itself
    /// was removed, its eviction grace starts again from that instant, the
    /// same grace a new address gets: a peer that restarts its session over
    /// the same link is withdrawn here and marked again only when its first
    /// authenticated frame arrives, and the address must not be evicted in
    /// between. Without it, as when the peer moved to another address, the
    /// grace is left alone, as a demotion leaves it: restarting it there
    /// would let one peer keep all its addresses protected by moving its
    /// frames among them.
    pub fn clear_verified(
        &mut self,
        addr: &TransportAddr,
        node: &NodeAddr,
        regrace: Option<tokio::time::Instant>,
    ) -> bool {
        match self.slots.get_mut(addr) {
            Some(slot) if slot.verified && slot.node.as_ref() == Some(node) => {
                slot.verified = false;
                if let Some(now) = regrace {
                    slot.grace_from = now;
                }
                true
            }
            _ => false,
        }
    }

    /// Whether the address `addr` is verified; `None` when nothing is held
    /// there.
    #[cfg(test)]
    pub fn is_verified(&self, addr: &TransportAddr) -> Option<bool> {
        self.slots.get(addr).map(|slot| slot.verified)
    }

    /// Remove every channel at an address, held or retiring. Returns how
    /// many went.
    pub fn remove(&mut self, addr: &TransportAddr) -> usize {
        let held = self.slots.remove(addr).map_or(0, |slot| slot.held.len());
        let before = self.retiring.len();
        self.retiring.retain(|(a, _)| a != addr);
        held + before - self.retiring.len()
    }

    /// Remove one channel, held or retiring. When the last held channel at
    /// an address goes, the address and its verdict go with it, so a later
    /// link there gets a fresh decision.
    pub fn remove_channel(&mut self, addr: &TransportAddr, id: u64) -> bool {
        if let Some(i) = self
            .retiring
            .iter()
            .position(|(a, c)| a == addr && c.id == id)
        {
            self.retiring.remove(i);
            return true;
        }
        let Some(slot) = self.slots.get_mut(addr) else {
            return false;
        };
        let Some(i) = slot.held.iter().position(|c| c.id == id) else {
            return false;
        };
        slot.held.remove(i);
        if slot.held.is_empty() {
            self.slots.remove(addr);
        }
        true
    }

    /// Record which direction to keep at `addr`, and retire the held
    /// channels of the other direction if one of the kept direction is
    /// held. Returns the ids retired.
    pub fn settle(&mut self, addr: &TransportAddr, keep_outbound: bool) -> Vec<u64> {
        let Some(slot) = self.slots.get_mut(addr) else {
            return Vec::new();
        };
        slot.verdict = Some(keep_outbound);
        let held: Vec<(u64, bool)> = slot.held.iter().map(|c| (c.id, c.outbound)).collect();
        let losers = settle(&held, keep_outbound);
        let (kept, gone): (Vec<_>, Vec<_>) = std::mem::take(&mut slot.held)
            .into_iter()
            .partition(|c| !losers.contains(&c.id));
        slot.held = kept;
        for mut conn in gone {
            conn.retire();
            self.retiring.push((addr.clone(), conn));
        }
        losers
    }

    /// Get all linked addresses.
    pub fn addrs(&self) -> Vec<TransportAddr> {
        self.slots.keys().cloned().collect()
    }

    /// The address a newcomer to a full pool may evict, if any.
    ///
    /// Only an unverified address that has had its grace may go. A node's
    /// duplicate addresses go first, so that one neighbour's address
    /// rotations displace only its own older addresses rather than another
    /// neighbour's only one; then the oldest. An address is as old as the
    /// channel its sends use. The grace is read from `grace_from`, so an
    /// address whose peer left it is protected for one grace and then ranks
    /// by its real age.
    fn victim(&self, now: tokio::time::Instant) -> Option<TransportAddr> {
        let evictable = |slot: &Slot<S>| {
            !slot.verified && now.saturating_duration_since(slot.grace_from) >= self.verify_grace
        };
        let duplicated = |slot: &Slot<S>| {
            slot.node.is_some_and(|node| {
                self.slots
                    .values()
                    .filter(|other| other.node == Some(node))
                    .count()
                    > 1
            })
        };
        let oldest = |dup_only: bool| {
            self.slots
                .iter()
                .filter(|(_, slot)| evictable(slot) && (!dup_only || duplicated(slot)))
                .filter_map(|(addr, slot)| slot.held.first().map(|c| (addr, c.established_at)))
                .min_by_key(|(_, at)| *at)
                .map(|(addr, _)| addr.clone())
        };
        oldest(true).or_else(|| oldest(false))
    }

    /// Count a refusal at `now`. A refusal after a quiet `BOUND_LOG_HOLD`
    /// starts a new run, closing any earlier one that was never reported.
    fn note_refusal(&mut self, now: tokio::time::Instant) -> Refused {
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
        Refused { first, ended }
    }

    /// Close a refusal run that has been quiet for `BOUND_LOG_HOLD`,
    /// returning its count for the caller to report.
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

    /// A distinct node identity per `n`.
    fn test_node(n: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        NodeAddr::from_bytes(bytes)
    }

    fn test_conn(n: u8) -> BleConnection<()> {
        channel(n, false, 0)
    }

    /// An inbound channel at `test_addr(n)` established at `at`.
    fn aged(n: u8, at: tokio::time::Instant) -> BleConnection<()> {
        let mut conn = test_conn(n);
        conn.established_at = at;
        conn
    }

    /// The insertion instant for tests that do not depend on time.
    fn now() -> tokio::time::Instant {
        tokio::time::Instant::now()
    }

    /// The grace every pool test runs with.
    const GRACE: Duration = Duration::from_secs(10);

    /// A pool of `max` holding an address `n` per entry of `slots`, each
    /// admitted at its instant and verified for node `n` when its flag is
    /// set.
    fn filled(max: usize, slots: &[(u8, tokio::time::Instant, bool)]) -> ConnectionPool<()> {
        let mut pool = ConnectionPool::new(max, GRACE);
        for &(n, at, verified) in slots {
            pool.insert(test_addr(n), aged(n, at), at).unwrap();
            if verified {
                let _ = pool.mark_verified(&test_addr(n), &test_node(n));
            }
        }
        pool
    }

    fn channel(n: u8, outbound: bool, id: u64) -> BleConnection<()> {
        BleConnection {
            stream: (),
            send_tx: tokio::sync::mpsc::channel(1).0,
            path_tx: tokio::sync::mpsc::channel(1).0,
            send_task: None,
            recv_task: None,
            send_mtu: 2048,
            recv_mtu: 2048,
            established_at: tokio::time::Instant::now(),
            addr: test_ble_addr(n),
            outbound,
            id,
        }
    }

    #[test]
    fn test_pool_basic_insert() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        assert!(pool.is_empty());

        pool.insert(test_addr(1), test_conn(1), now()).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());
        assert!(pool.contains(&test_addr(1)));
    }

    #[test]
    fn test_pool_remove() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        pool.insert(test_addr(1), test_conn(1), now()).unwrap();
        assert_eq!(pool.remove(&test_addr(1)), 1);
        assert!(pool.is_empty());
    }

    /// A full pool evicts its oldest unverified address once that address
    /// has had its grace, never an older verified one.
    #[test]
    fn a_full_pool_evicts_its_oldest_unverified_address_once_past_its_grace() {
        let t0 = now();
        let secs = Duration::from_secs;
        let mut pool = filled(
            7,
            &[
                (1, t0, true),
                (2, t0, true),
                (3, t0, true),
                (4, t0, true),
                (5, t0, true),
                (6, t0 + secs(1), false),
                (7, t0 + secs(2), false),
            ],
        );
        assert!(pool.is_full());

        let at = t0 + secs(20);
        let admitted = pool.insert(test_addr(8), aged(8, at), at).unwrap();
        assert_eq!(admitted.admission, Admission::Admit);
        assert_eq!(admitted.evicted, Some(test_addr(6)));
        assert_eq!(pool.len(), 7);
        assert!(pool.contains(&test_addr(8)));
    }

    /// A full pool of addresses carrying sessions refuses a newcomer rather
    /// than evicting one of them, however old they are.
    #[test]
    fn a_full_pool_of_verified_addresses_refuses_an_unverified_newcomer() {
        let t0 = now();
        let slots: Vec<_> = (1..=7).map(|n| (n, t0, true)).collect();
        let mut pool = filled(7, &slots);
        let later = t0 + Duration::from_secs(60);
        assert!(pool.insert(test_addr(8), aged(8, later), later).is_err());
        assert_eq!(pool.len(), 7);
        for n in 1..=7 {
            assert!(pool.contains(&test_addr(n)), "verified address {n} is kept");
        }
        assert!(!pool.contains(&test_addr(8)), "the newcomer is refused");
    }

    /// A newly admitted address has its grace to complete a handshake:
    /// newcomers to a full pool are refused rather than evicting it.
    #[test]
    fn a_newly_admitted_unverified_address_is_not_evicted_before_its_grace() {
        let t0 = now();
        let secs = Duration::from_secs;
        let t = t0 + secs(100);
        let mut slots: Vec<_> = (1..=6).map(|n| (n, t0, true)).collect();
        slots.push((7, t, false));
        let mut pool = filled(7, &slots);

        let at = t + secs(1);
        assert_eq!(
            pool.insert(test_addr(8), aged(8, at), at),
            Err(Refused {
                first: true,
                ended: None
            })
        );
        let at = t + secs(2);
        assert_eq!(
            pool.insert(test_addr(9), aged(9, at), at),
            Err(Refused {
                first: false,
                ended: None
            })
        );
        assert!(
            pool.contains(&test_addr(7)),
            "the honest address keeps its slot"
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
        let refused = |first, ended| Err(Refused { first, ended });
        let ended = |r: Result<Admitted, Refused>| r.unwrap().ended;
        let mut pool = filled(1, &[(1, t0, true)]);
        for (k, first) in [(0, true), (10, false), (20, false)] {
            let at = t0 + secs(k);
            assert_eq!(
                pool.insert(test_addr(2), aged(2, at), at),
                refused(first, None)
            );
        }
        let last = t0 + secs(20);

        // Room made, then an admission inside the minute: the run stays open.
        pool.remove(&test_addr(1));
        let at = last + secs(30);
        assert_eq!(ended(pool.insert(test_addr(3), aged(3, at), at)), None);
        // An admission a minute after the last refusal closes it.
        pool.remove(&test_addr(3));
        let at = last + secs(61);
        assert_eq!(ended(pool.insert(test_addr(4), aged(4, at), at)), Some(3));
        let _ = pool.mark_verified(&test_addr(4), &test_node(4));
        let at = last + secs(62);
        assert_eq!(
            pool.insert(test_addr(5), aged(5, at), at),
            refused(true, None),
            "the next refusal starts a new run"
        );

        // A run that ends with no insert is reported by the next refusal.
        let mut pool = filled(1, &[(1, t0, true)]);
        for k in [0, 1] {
            let at = t0 + secs(k);
            let _ = pool.insert(test_addr(2), aged(2, at), at);
        }
        let at = t0 + secs(91);
        assert_eq!(
            pool.insert(test_addr(2), aged(2, at), at),
            refused(true, Some(2))
        );
    }

    /// Verifying a second address for a node demotes the first and closes
    /// nothing; the demoted address is the first to go once past its grace.
    #[test]
    fn a_second_verification_demotes_the_first_address_and_leaves_it_pooled() {
        let t0 = now();
        let mut pool = filled(7, &[(1, t0, false), (2, t0, false)]);

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
        assert_eq!(pool.is_verified(&test_addr(1)), Some(false));
        assert_eq!(pool.is_verified(&test_addr(2)), Some(true));
        // Marking the verified address again changes nothing.
        assert_eq!(
            pool.mark_verified(&test_addr(2), &test_node(1)),
            Verify::Marked { demoted: vec![] }
        );
        assert_eq!(
            pool.mark_verified(&test_addr(9), &test_node(1)),
            Verify::Absent
        );

        for n in 3..=7 {
            pool.insert(test_addr(n), aged(n, t0), t0).unwrap();
            let _ = pool.mark_verified(&test_addr(n), &test_node(n));
        }
        let at = t0 + Duration::from_secs(20);
        let admitted = pool.insert(test_addr(8), aged(8, at), at).unwrap();
        assert_eq!(admitted.evicted, Some(test_addr(1)));
    }

    /// A node's duplicate address goes before another node's only address,
    /// even an older one.
    #[test]
    fn a_full_pool_evicts_a_nodes_duplicate_before_another_nodes_only_address() {
        let t0 = now();
        let secs = Duration::from_secs;
        let mut pool = filled(
            3,
            &[
                (1, t0, false),
                (2, t0 + secs(1), false),
                (3, t0 + secs(2), false),
            ],
        );
        // Node 3's only address, which its peer has left, then two addresses
        // node 1's peer has used and left.
        let _ = pool.mark_verified(&test_addr(1), &test_node(3));
        assert!(pool.clear_verified(&test_addr(1), &test_node(3), None));
        let _ = pool.mark_verified(&test_addr(2), &test_node(1));
        let _ = pool.mark_verified(&test_addr(3), &test_node(1));
        assert!(pool.clear_verified(&test_addr(3), &test_node(1), None));

        let at = t0 + secs(20);
        let admitted = pool.insert(test_addr(4), aged(4, at), at).unwrap();
        assert_eq!(
            admitted.evicted,
            Some(test_addr(2)),
            "node 1's older duplicate goes first"
        );
        let at = t0 + secs(21);
        let admitted = pool.insert(test_addr(5), aged(5, at), at).unwrap();
        assert_eq!(
            admitted.evicted,
            Some(test_addr(1)),
            "with no duplicate left, the oldest goes"
        );
    }

    /// An address its peer moved off keeps the grace it had: once that has
    /// passed it is evictable at once, so a peer moving its frames among its
    /// own addresses protects only the one it is on.
    #[test]
    fn an_address_its_peer_moved_off_keeps_the_grace_it_had() {
        let t0 = now();
        let mut pool = filled(2, &[(1, t0, true), (2, t0, false)]);

        let moved = t0 + Duration::from_secs(60);
        assert!(pool.clear_verified(&test_addr(1), &test_node(1), None));
        let _ = pool.mark_verified(&test_addr(2), &test_node(1));
        let admitted = pool.insert(test_addr(3), aged(3, moved), moved).unwrap();
        assert_eq!(
            admitted.evicted,
            Some(test_addr(1)),
            "the address the peer moved off is evicted without a new grace"
        );
    }

    /// An address whose peer left it gets the grace again, then ranks by its
    /// age.
    #[test]
    fn a_withdrawn_address_gets_the_grace_again() {
        let t0 = now();
        let secs = Duration::from_secs;
        let mut pool = filled(2, &[(1, t0, true), (2, t0 + secs(1), false)]);

        assert!(pool.clear_verified(&test_addr(1), &test_node(1), Some(t0 + secs(60))));
        assert_eq!(pool.get(&test_addr(1)).unwrap().established_at, t0);

        let at = t0 + secs(61);
        let admitted = pool.insert(test_addr(3), aged(3, at), at).unwrap();
        assert_eq!(
            admitted.evicted,
            Some(test_addr(2)),
            "the withdrawn address is inside its new grace"
        );
        let at = t0 + secs(62);
        assert!(pool.insert(test_addr(4), aged(4, at), at).is_err());
        let at = t0 + Duration::from_millis(70_500);
        let admitted = pool.insert(test_addr(5), aged(5, at), at).unwrap();
        assert_eq!(
            admitted.evicted,
            Some(test_addr(1)),
            "once past its new grace the withdrawn address goes"
        );
    }

    /// Verification belongs to the address, so the channels held beside its
    /// first, and a settlement among them, leave it in place.
    #[test]
    fn a_verified_address_stays_verified_while_its_channels_settle() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        pool.insert(test_addr(1), channel(1, false, 1), now())
            .unwrap();
        let _ = pool.mark_verified(&test_addr(1), &test_node(1));
        pool.insert(test_addr(1), channel(1, true, 2), now())
            .unwrap();
        assert_eq!(pool.settle(&test_addr(1), true), vec![1]);
        assert_eq!(pool.is_verified(&test_addr(1)), Some(true));

        // Once the last held channel goes, the address goes with its flag,
        // and a later link there starts unverified.
        assert!(pool.remove_channel(&test_addr(1), 2));
        pool.insert(test_addr(1), channel(1, false, 3), now())
            .unwrap();
        assert_eq!(pool.is_verified(&test_addr(1)), Some(false));
    }

    #[test]
    fn a_second_channel_at_an_address_is_held_not_counted() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(1, GRACE);
        pool.insert(test_addr(1), channel(1, true, 1), now())
            .unwrap();

        // The peer's own dial arrives at the same address: held beside the
        // first, not replacing it, and not taking a pool slot.
        let result = pool
            .insert(test_addr(1), channel(1, false, 2), now())
            .unwrap();
        assert_eq!(result.admission, Admission::Hold);
        assert_eq!(result.evicted, None);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.held(&test_addr(1)), vec![(1, true), (2, false)]);
        assert_eq!(
            pool.get(&test_addr(1)).unwrap().id,
            1,
            "sends use the oldest"
        );
    }

    #[test]
    fn a_channel_ending_removes_only_itself() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        pool.insert(test_addr(1), channel(1, true, 1), now())
            .unwrap();
        pool.insert(test_addr(1), channel(1, false, 2), now())
            .unwrap();

        assert!(pool.remove_channel(&test_addr(1), 1));
        assert_eq!(pool.held(&test_addr(1)), vec![(2, false)]);
        assert!(!pool.remove_channel(&test_addr(1), 1), "already gone");
        assert!(pool.remove_channel(&test_addr(1), 2));
        assert!(
            !pool.contains(&test_addr(1)),
            "the last channel takes the address"
        );
    }

    #[test]
    fn settling_retires_the_other_direction_and_keeps_the_verdict() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        pool.insert(test_addr(1), channel(1, false, 1), now())
            .unwrap();
        pool.insert(test_addr(1), channel(1, true, 2), now())
            .unwrap();

        assert_eq!(pool.settle(&test_addr(1), true), vec![1]);
        assert_eq!(pool.held(&test_addr(1)), vec![(2, true)]);
        assert_eq!(pool.retiring(&test_addr(1)), vec![1]);

        // A later inbound at a settled address is retired on arrival.
        let late = pool
            .insert(test_addr(1), channel(1, false, 3), now())
            .unwrap();
        assert_eq!(late.admission, Admission::Retire);
        assert_eq!(late.retired, vec![3]);
        assert_eq!(pool.held(&test_addr(1)), vec![(2, true)]);

        // Removing the address takes the retiring channels with it.
        assert_eq!(pool.remove(&test_addr(1)), 3);
        assert!(pool.retiring(&test_addr(1)).is_empty());
    }

    #[test]
    fn a_verdict_waits_for_the_winning_channel() {
        let mut pool: ConnectionPool<()> = ConnectionPool::new(7, GRACE);
        pool.insert(test_addr(1), channel(1, false, 1), now())
            .unwrap();

        // Only the losing direction is held: nothing is retired, so a side
        // never loses its only link to a verdict.
        assert!(pool.settle(&test_addr(1), true).is_empty());
        assert_eq!(pool.held(&test_addr(1)), vec![(1, false)]);

        // The winner arrives and replaces it.
        let result = pool
            .insert(test_addr(1), channel(1, true, 2), now())
            .unwrap();
        assert_eq!(result.admission, Admission::Replace);
        assert_eq!(result.retired, vec![1]);
        assert_eq!(pool.held(&test_addr(1)), vec![(2, true)]);
    }

    /// Every input combination: 0 or 1 held outbound, 0 to 2 held inbound,
    /// three verdicts, two newcomer directions. Combinations a conforming
    /// pair of nodes cannot reach are still pinned, so the result for each
    /// is a decision rather than an accident.
    #[test]
    fn admission_table() {
        use Admission::*;
        let none = None;
        let out = Some(true);
        let inb = Some(false);
        // (held_out, held_in, verdict, newcomer outbound, expected, reachable)
        let table = [
            (0, 0, none, true, Admit, true),
            (0, 0, none, false, Admit, true),
            (0, 0, out, true, Admit, false),
            (0, 0, out, false, Admit, false),
            (0, 0, inb, true, Admit, false),
            (0, 0, inb, false, Admit, false),
            (1, 0, none, true, Retire, true),
            (1, 0, none, false, Hold, true),
            (1, 0, out, true, Retire, true),
            (1, 0, out, false, Retire, true),
            (1, 0, inb, true, Retire, true),
            (1, 0, inb, false, Replace, true),
            (0, 1, none, true, Hold, true),
            (0, 1, none, false, Hold, true),
            (0, 1, out, true, Replace, true),
            (0, 1, out, false, Hold, true),
            (0, 1, inb, true, Retire, true),
            (0, 1, inb, false, Hold, true),
            (0, 2, none, true, Hold, true),
            (0, 2, none, false, Hold, false),
            (0, 2, out, true, Replace, true),
            (0, 2, out, false, Hold, false),
            (0, 2, inb, true, Retire, true),
            (0, 2, inb, false, Hold, false),
            (1, 1, none, true, Retire, true),
            (1, 1, none, false, Hold, true),
            (1, 1, out, true, Retire, false),
            (1, 1, out, false, Hold, false),
            (1, 1, inb, true, Retire, false),
            (1, 1, inb, false, Hold, false),
            (1, 2, none, true, Retire, false),
            (1, 2, none, false, Retire, false),
            (1, 2, out, true, Retire, false),
            (1, 2, out, false, Retire, false),
            (1, 2, inb, true, Retire, false),
            (1, 2, inb, false, Retire, false),
        ];
        assert_eq!(table.len(), 36);
        for (held_out, held_in, verdict, outbound, expected, reachable) in table {
            assert_eq!(
                admit(held_out, held_in, verdict, outbound),
                expected,
                "held_out={held_out} held_in={held_in} verdict={verdict:?} \
                 outbound={outbound} (reachable: {reachable})"
            );
        }
    }

    #[test]
    fn settlement_table() {
        // (held, keep_outbound, retired)
        type Row = (&'static [(u64, bool)], bool, &'static [u64]);
        let table: [Row; 10] = [
            (&[], true, &[]),
            (&[(1, true)], true, &[]),
            (&[(1, true)], false, &[]),
            (&[(1, false)], true, &[]),
            (&[(1, false)], false, &[]),
            (&[(1, true), (2, false)], true, &[2]),
            (&[(1, true), (2, false)], false, &[1]),
            (&[(1, false), (2, false), (3, true)], true, &[1, 2]),
            (&[(1, false), (2, false), (3, true)], false, &[3]),
            (&[(1, false), (2, false)], true, &[]),
        ];
        for (held, keep_outbound, retired) in table {
            assert_eq!(
                settle(held, keep_outbound),
                retired,
                "held={held:?} keep_outbound={keep_outbound}"
            );
        }
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
        pool.insert(test_addr(1), test_conn(1), now()).unwrap();
        pool.insert(test_addr(2), test_conn(2), now()).unwrap();

        let mut addrs = pool.addrs();
        addrs.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        assert_eq!(addrs.len(), 2);
    }
}
