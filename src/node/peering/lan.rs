//! LAN (mDNS) discovery candidates held between ticks — sans-IO.
//!
//! An mDNS advert names an npub and an address, and anyone on the link can
//! send one. Dialling every advert at once let a sender on the link start an
//! unbounded number of handshakes under fresh keys. Instead each advert that
//! names an address on this node's links becomes a pending (node, address)
//! pair here, and the driver offers the set to the reconcile core each tick,
//! which dials within the discovery budget and keeps unconfigured LAN
//! handshakes in flight to at most [`MAX_LAN_DIALS_IN_FLIGHT`], and to at most
//! [`MAX_LAN_DIALS_PER_ADDR`] for any one address. Pairs the core
//! does not dial carry over to later ticks until they are dialled, connect
//! by another path, leave this node's links or expire.
//!
//! Time and randomness are inputs. `now_ms` is milliseconds on a monotonic
//! clock with a fixed origin (the node's uptime), never wall-clock time, so a
//! clock step cannot expire every held pair at once; mDNS reports an advert
//! again only when one of its records changes, so a pair lost that way would
//! not come back.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rand::RngExt;
use rand::seq::SliceRandom;

use crate::PeerIdentity;
use crate::identity::NodeAddr;
use crate::transport::TransportId;
use crate::utils::onlink::OnLinkPrefixes;

/// Upper bound on held LAN candidate pairs.
///
/// A LAN rarely holds more than a few dozen FIPS nodes, each offering a
/// handful of addresses, so 64 holds every honest pair a busy segment
/// produces between dials. A sender on the link can keep the set full with
/// about 64 fresh npubs per ten minutes; each newcomer then displaces a
/// random unconfigured pair, so an honest unconfigured pair survives a
/// sustained flood only by being dialled first. Not measured.
pub(in crate::node) const MAX_PENDING_LAN_CANDIDATES: usize = 64;

/// Upper bound on held addresses per node.
///
/// A dual-stack host on two links offers about four. Every node's npub is in
/// its advert, so a sender on the link can fill a node's slots with bogus
/// addresses before the honest advert arrives; the honest address is then
/// refused, and since mDNS reports an advert again only when it changes, it
/// is not dialled from that advert for as long as the sender keeps the slots
/// filled (each slot frees after a handshake timeout). The node is still
/// reached when it dials us or by another discovery path. Not measured.
pub(in crate::node) const MAX_LAN_ADDRS_PER_NODE: usize = 4;

/// How long a held pair waits to be dialled before it is dropped.
///
/// Ten minutes is far longer than the few ticks an honest pair waits behind
/// the dial pacing; a pair a sender planted stays at most this long unless it
/// advertises again. Not measured.
pub(in crate::node) const PENDING_LAN_CANDIDATE_MAX_AGE: Duration = Duration::from_secs(600);

/// Upper bound on unconfigured LAN handshakes in flight at once.
///
/// Honest LAN discovery completes its handshakes within a tick or two, so
/// eight in flight never pace it. Dials to adverts that never complete hold
/// at most eight handshake slots, so a flood paces honest unconfigured dials
/// to about eight per handshake timeout instead of exhausting handshake
/// state. Configured peers are not counted against it. Not measured.
pub(in crate::node) const MAX_LAN_DIALS_IN_FLIGHT: usize = 8;

/// Upper bound on unconfigured LAN handshakes in flight to one IP address.
///
/// Several FIPS nodes share an address only when they run on one host, and
/// their handshakes complete within a tick or two, so two in flight barely
/// pace them. The mDNS browser ties an advert to its host only through the
/// first characters of the npub, and nothing checks the npub until the
/// handshake, so a sender on the link can mint any number of npubs whose
/// adverts resolve to the address of a FIPS node on another of this node's
/// links, at ports of its choosing. This bounds the handshakes such adverts
/// aim at one host at once; the in-flight cap alone would let them hold all
/// eight. Not measured.
pub(in crate::node) const MAX_LAN_DIALS_PER_ADDR: usize = 2;

/// How long the set must stay below [`MAX_PENDING_LAN_CANDIDATES`] before the
/// set-full warning is re-armed, so a flood that pushes the set across its
/// bound once per advert produces at most two lines a minute.
const BOUND_LOG_HOLD: Duration = Duration::from_secs(60);

/// One held LAN candidate: a node and one address it was advertised at.
#[derive(Clone, Debug)]
pub(in crate::node) struct PendingPair {
    /// The advertised node.
    pub node: NodeAddr,
    /// The advertised identity, which the handshake authenticates.
    pub identity: PeerIdentity,
    /// The UDP transport to dial over.
    pub transport_id: TransportId,
    /// The advertised address.
    pub addr: SocketAddr,
    /// OS indexes of the interfaces the advert's address record arrived on.
    pub interfaces: Vec<u32>,
    /// Monotonic milliseconds when the pair was first offered; set by
    /// [`PendingLan::offer`].
    pub first_seen_ms: u64,
}

/// What [`PendingLan::offer`] did with a pair.
#[derive(Debug)]
pub(in crate::node) enum LanOffer {
    /// The pair is now held.
    Held,
    /// The same node and address is already held; its first time is kept.
    Duplicate,
    /// The node already holds [`MAX_LAN_ADDRS_PER_NODE`] addresses; the first
    /// ones are kept.
    RefusedPerNode,
    /// The set was full; the pair took the place of `displaced`, an
    /// unconfigured pair chosen at random. `first_at_bound` is set on the
    /// first offer to find the set full since it last stayed below its bound
    /// for a minute.
    Replaced {
        displaced: Box<PendingPair>,
        first_at_bound: bool,
    },
    /// The set was full of configured pairs, so nothing could make room.
    Refused { first_at_bound: bool },
}

/// The held LAN candidates, the unconfigured nodes dialled from them that
/// are still connecting, and the set-full log latch.
#[derive(Debug, Default)]
pub(in crate::node) struct PendingLan {
    /// Held pairs in arrival order.
    pairs: Vec<PendingPair>,
    /// Unconfigured nodes dialled from this set and still connecting, with
    /// the address each was dialled at.
    dialed: HashMap<NodeAddr, IpAddr>,
    latched: bool,
    /// Offers that found the set full since the latch was set.
    at_bound: u64,
    /// When the set was first seen below its bound while latched.
    below_since_ms: Option<u64>,
}

/// Whether an advertised LAN address is on the link its advert arrived on.
///
/// An IPv6 link-local address is on-link by definition when it names its
/// interface (a non-zero scope, which is the interface the record arrived
/// on); without one it cannot be dialled. Any other address must lie inside
/// a prefix held by one of `interfaces`, the interfaces the address record
/// arrived on. A prefix of another interface does not count: a sender on one
/// link could otherwise aim dials into the node's other networks, such as a
/// VPN or a container bridge. With no arrival interface known, the address
/// is refused. Only the dial target is judged: who sent the advert is
/// unknown.
///
/// mdns-sd does not report the interface the advert itself (its SRV record)
/// arrived on, only that of each address record, and it resolves a host's
/// addresses on every interface. The mDNS browser therefore also refuses an
/// advert whose service host is not the advertised node's own FIPS host
/// name, so a sender cannot point the address lookup at an arbitrary machine
/// on another link. It can still name the host of a FIPS node on another of
/// this node's links, with a port of its choosing, and under npubs minted to
/// share that node's host name; [`MAX_LAN_DIALS_PER_ADDR`] bounds the dials
/// that aims at the host at once.
pub(in crate::node) fn lan_target_on_link(
    addr: SocketAddr,
    interfaces: &[u32],
    on_link: &OnLinkPrefixes,
) -> bool {
    match addr {
        SocketAddr::V6(v6) if v6.ip().is_unicast_link_local() => v6.scope_id() != 0,
        _ => on_link.contains_on(addr.ip(), interfaces),
    }
}

impl PendingLan {
    /// Offer one advertised pair, stamping it with `now_ms` as its first
    /// sighting. `configured` is the current set of configured nodes, read at
    /// each call so a configuration reload applies to pairs already held.
    pub(in crate::node) fn offer(
        &mut self,
        mut pair: PendingPair,
        configured: &HashSet<NodeAddr>,
        now_ms: u64,
        rng: &mut impl rand::Rng,
    ) -> LanOffer {
        pair.first_seen_ms = now_ms;
        if self
            .pairs
            .iter()
            .any(|held| held.node == pair.node && held.addr == pair.addr)
        {
            return LanOffer::Duplicate;
        }
        if self
            .pairs
            .iter()
            .filter(|held| held.node == pair.node)
            .count()
            >= MAX_LAN_ADDRS_PER_NODE
        {
            return LanOffer::RefusedPerNode;
        }
        if self.pairs.len() < MAX_PENDING_LAN_CANDIDATES {
            self.pairs.push(pair);
            return LanOffer::Held;
        }

        let first_at_bound = !self.latched;
        self.latched = true;
        self.at_bound = self.at_bound.saturating_add(1);
        self.below_since_ms = None;

        let replaceable: Vec<usize> = (0..self.pairs.len())
            .filter(|&i| !configured.contains(&self.pairs[i].node))
            .collect();
        if replaceable.is_empty() {
            return LanOffer::Refused { first_at_bound };
        }
        let victim = replaceable[rng.random_range(0..replaceable.len())];
        let displaced = Box::new(self.pairs.remove(victim));
        self.pairs.push(pair);
        LanOffer::Replaced {
            displaced,
            first_at_bound,
        }
    }

    /// Drop pairs older than [`PENDING_LAN_CANDIDATE_MAX_AGE`], and release
    /// the set-full latch once the set has stayed below its bound for a
    /// minute, returning the offers that found it full meanwhile.
    pub(in crate::node) fn expire(&mut self, now_ms: u64) -> Option<u64> {
        let max_age_ms = PENDING_LAN_CANDIDATE_MAX_AGE.as_millis() as u64;
        self.pairs
            .retain(|pair| now_ms.saturating_sub(pair.first_seen_ms) < max_age_ms);
        if !self.latched {
            return None;
        }
        if self.pairs.len() >= MAX_PENDING_LAN_CANDIDATES {
            self.below_since_ms = None;
            return None;
        }
        let since = *self.below_since_ms.get_or_insert(now_ms);
        if now_ms.saturating_sub(since) < BOUND_LOG_HOLD.as_millis() as u64 {
            return None;
        }
        let at_bound = self.at_bound;
        self.latched = false;
        self.at_bound = 0;
        self.below_since_ms = None;
        Some(at_bound)
    }

    /// Drop every pair of a node that is now connected.
    pub(in crate::node) fn prune_connected(&mut self, connected: &HashSet<NodeAddr>) {
        self.pairs.retain(|pair| !connected.contains(&pair.node));
    }

    /// Drop pairs whose address is no longer on this node's links, returning
    /// how many went.
    pub(in crate::node) fn retain_on_link(&mut self, on_link: &OnLinkPrefixes) -> usize {
        let before = self.pairs.len();
        self.pairs
            .retain(|pair| lan_target_on_link(pair.addr, &pair.interfaces, on_link));
        before - self.pairs.len()
    }

    /// The held pairs in dial order: configured pairs first, in arrival
    /// order, then the rest in an order shuffled with `rng`.
    ///
    /// Unconfigured pairs are left out, for this tick, once their address
    /// already has [`MAX_LAN_DIALS_PER_ADDR`] distinct nodes in flight or
    /// listed ahead of them; they stay held for a later tick.
    pub(in crate::node) fn ordered(
        &self,
        configured: &HashSet<NodeAddr>,
        rng: &mut impl rand::Rng,
    ) -> Vec<&PendingPair> {
        let mut out: Vec<&PendingPair> = self
            .pairs
            .iter()
            .filter(|pair| configured.contains(&pair.node))
            .collect();
        let mut rest: Vec<&PendingPair> = self
            .pairs
            .iter()
            .filter(|pair| !configured.contains(&pair.node))
            .collect();
        rest.shuffle(rng);
        let mut per_addr: HashMap<IpAddr, HashSet<NodeAddr>> = HashMap::new();
        for (node, ip) in &self.dialed {
            per_addr.entry(*ip).or_default().insert(*node);
        }
        rest.retain(|pair| {
            let nodes = per_addr.entry(pair.addr.ip().to_canonical()).or_default();
            nodes.contains(&pair.node)
                || (nodes.len() < MAX_LAN_DIALS_PER_ADDR && nodes.insert(pair.node))
        });
        out.extend(rest);
        out
    }

    /// Remove a pair that is being dialled.
    pub(in crate::node) fn take(&mut self, node: &NodeAddr, addr: SocketAddr) {
        self.pairs
            .retain(|pair| !(pair.node == *node && pair.addr == addr));
    }

    /// Record an unconfigured node dialled from this set at `addr`.
    pub(in crate::node) fn note_dialed(&mut self, node: NodeAddr, addr: SocketAddr) {
        self.dialed.insert(node, addr.ip().to_canonical());
    }

    /// Forget dialled nodes that are no longer connecting.
    pub(in crate::node) fn prune_dialed(&mut self, connecting: &HashSet<NodeAddr>) {
        self.dialed.retain(|node, _| connecting.contains(node));
    }

    /// Unconfigured LAN dials still connecting.
    pub(in crate::node) fn in_flight(&self) -> usize {
        self.dialed.len()
    }

    /// Number of held pairs.
    pub(in crate::node) fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Whether no pair is held.
    pub(in crate::node) fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// Whether the set-full latch is set.
    #[cfg(test)]
    pub(in crate::node) fn is_latched(&self) -> bool {
        self.latched
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;
    use crate::identity::Identity;
    use crate::node::peering::reconcile::{
        Budget, Candidate, DiscoveryPools, Gate, Observed, PeeringAction, PeeringReconciler, Policy,
    };
    use crate::transport::TransportAddr;

    fn fresh() -> PeerIdentity {
        PeerIdentity::from_pubkey(Identity::generate().pubkey())
    }

    fn pair(identity: PeerIdentity, addr: &str) -> PendingPair {
        PendingPair {
            node: *identity.node_addr(),
            identity,
            transport_id: TransportId::new(1),
            addr: addr.parse().unwrap(),
            interfaces: vec![1],
            first_seen_ms: 0,
        }
    }

    /// Prefixes held by interface 1, the one [`pair`]'s adverts arrive on.
    fn on_one(entries: &[(&str, u8)]) -> OnLinkPrefixes {
        OnLinkPrefixes::from_indexed(
            entries
                .iter()
                .map(|(text, len)| (text.parse().unwrap(), *len, Some(1))),
        )
    }

    fn none() -> HashSet<NodeAddr> {
        HashSet::new()
    }

    fn policy() -> Policy {
        Policy {
            auto_connect_peers: Vec::new(),
            max_peers: 0,
            max_connections: 0,
            max_links: 0,
            retry_base_interval_ms: 1_000,
            retry_max_backoff_ms: 60_000,
            retry_max_retries: 5,
            handshake_timeout_ms: 30_000,
            open_discovery_enabled: false,
            open_discovery_max_pending: 32,
            open_discovery_expires_ms: 600_000,
        }
    }

    fn budget() -> Budget {
        Budget {
            handshake_slots: 1_000,
            link_slots: 1_000,
            peer_slots: 1_000,
            admission_ok: true,
            discovery_per_tick: 16,
            retry_per_tick: 16,
            per_peer_cap: 4,
        }
    }

    /// A one-second-tick model of the driver: offers, the reconcile core,
    /// `take`, `note_dialed` and `prune_dialed`, with dials to `invented`
    /// nodes staying connecting for 30 ticks and never completing, and dials
    /// to anyone else completing at once.
    struct Sim {
        lan: PendingLan,
        core: PeeringReconciler,
        rng: StdRng,
        configured: HashSet<NodeAddr>,
        invented: HashSet<NodeAddr>,
        connected: HashSet<NodeAddr>,
        connecting: HashMap<NodeAddr, u64>,
        dials: Vec<(u64, NodeAddr, SocketAddr)>,
    }

    impl Sim {
        fn new(seed: u64) -> Self {
            Self {
                lan: PendingLan::default(),
                core: PeeringReconciler::default(),
                rng: StdRng::seed_from_u64(seed),
                configured: HashSet::new(),
                invented: HashSet::new(),
                connected: HashSet::new(),
                connecting: HashMap::new(),
                dials: Vec::new(),
            }
        }

        fn invent(&mut self, count: usize, tick: u64) -> Vec<PendingPair> {
            (0..count)
                .map(|i| {
                    let id = fresh();
                    self.invented.insert(*id.node_addr());
                    pair(id, &format!("192.168.1.{}:{}", 1 + i % 250, 10_000 + tick))
                })
                .collect()
        }

        fn tick(&mut self, tick: u64, offers: Vec<PendingPair>) {
            let now_ms = tick * 1_000;
            self.connecting.retain(|_, until| *until > tick);
            self.lan.expire(now_ms);
            self.lan.prune_connected(&self.connected);
            for offer in offers {
                self.lan
                    .offer(offer, &self.configured, now_ms, &mut self.rng);
            }
            let connecting: HashSet<NodeAddr> = self.connecting.keys().copied().collect();
            self.lan.prune_dialed(&connecting);
            let lan: Vec<Candidate> = self
                .lan
                .ordered(&self.configured, &mut self.rng)
                .into_iter()
                .map(|p| Candidate {
                    transport_id: p.transport_id,
                    remote_addr: TransportAddr::from_string(&p.addr.to_string()),
                    identity: Some(p.identity),
                    active_refresh: false,
                })
                .collect();
            let pools = DiscoveryPools {
                lan,
                lan_configured: self.configured.clone(),
                ..DiscoveryPools::default()
            };
            let observed = Observed {
                connected: self.connected.clone(),
                connecting,
                lan_in_flight: self.lan.in_flight(),
                ..Observed::default()
            };
            let actions = self.core.reconcile_opportunistic(
                &policy(),
                &observed,
                &budget(),
                &pools,
                now_ms,
                Gate::Reconciling,
            );
            for action in actions {
                let PeeringAction::Connect(c) = action else {
                    continue;
                };
                let node = *c.identity.unwrap().node_addr();
                let addr: SocketAddr = c.remote_addr.as_str().unwrap().parse().unwrap();
                self.lan.take(&node, addr);
                if !self.configured.contains(&node) {
                    self.lan.note_dialed(node, addr);
                }
                self.dials.push((tick, node, addr));
                if self.invented.contains(&node) {
                    self.connecting.insert(node, tick + 30);
                } else {
                    self.connected.insert(node);
                }
            }
            assert!(self.lan.len() <= MAX_PENDING_LAN_CANDIDATES);
            let mut per_node: HashMap<NodeAddr, usize> = HashMap::new();
            for held in &self.lan.pairs {
                *per_node.entry(held.node).or_default() += 1;
            }
            assert!(per_node.values().all(|n| *n <= MAX_LAN_ADDRS_PER_NODE));
        }

        fn first_dial_of(&self, node: &NodeAddr) -> Option<u64> {
            self.dials.iter().find(|d| d.1 == *node).map(|d| d.0)
        }
    }

    #[test]
    fn an_honest_candidate_held_behind_a_flood_burst_is_dialled_within_the_bound() {
        let mut sim = Sim::new(1);
        let honest = fresh();
        for tick in 0..=250u64 {
            let mut offers = Vec::new();
            if tick == 0 {
                offers = sim.invent(64, tick);
            }
            if tick == 10 {
                // Refill the set to its bound just before the honest advert.
                offers = sim.invent(MAX_LAN_DIALS_IN_FLIGHT, tick);
                offers.push(pair(honest, "192.168.1.200:2121"));
            }
            sim.tick(tick, offers);
        }
        let dialled = sim.first_dial_of(honest.node_addr());
        assert!(
            dialled.is_some_and(|t| t <= 250),
            "honest dialled at {dialled:?}"
        );
    }

    #[test]
    fn below_the_dial_rate_a_flood_only_delays_an_honest_lan_candidate() {
        let mut sim = Sim::new(2);
        let honest = fresh();
        for tick in 0..=120u64 {
            let mut offers = Vec::new();
            if tick % 30 == 0 {
                offers = sim.invent(MAX_LAN_DIALS_IN_FLIGHT - 1, tick);
            }
            if tick == 10 {
                offers.push(pair(honest, "192.168.1.200:2121"));
            }
            sim.tick(tick, offers);
        }
        let dialled = sim.first_dial_of(honest.node_addr());
        assert!(
            dialled.is_some_and(|t| t < 40),
            "honest dialled at {dialled:?}"
        );
    }

    #[test]
    fn a_configured_lan_candidate_is_dialled_through_a_sustained_flood() {
        let mut sim = Sim::new(3);
        let configured = fresh();
        sim.configured.insert(*configured.node_addr());
        for tick in 0..120u64 {
            let mut offers = sim.invent(40, tick);
            if tick == 10 {
                offers.insert(20, pair(configured, "192.168.1.201:2121"));
            }
            sim.tick(tick, offers);
        }
        let dialled = sim.first_dial_of(configured.node_addr());
        assert!(
            dialled.is_some_and(|t| t == 10 || t == 11),
            "configured dialled at {dialled:?}"
        );
    }

    #[test]
    fn a_configured_lan_candidate_is_never_displaced_by_unconfigured_newcomers() {
        let mut lan = PendingLan::default();
        let mut rng = StdRng::seed_from_u64(4);
        let configured_id = fresh();
        let configured: HashSet<NodeAddr> = [*configured_id.node_addr()].into_iter().collect();
        for i in 0..63 {
            lan.offer(
                pair(fresh(), &format!("192.168.1.{}:1", i + 1)),
                &configured,
                0,
                &mut rng,
            );
        }
        lan.offer(
            pair(configured_id, "192.168.1.100:1"),
            &configured,
            0,
            &mut rng,
        );
        for _ in 0..1000 {
            lan.offer(pair(fresh(), "192.168.1.200:1"), &configured, 0, &mut rng);
        }
        assert_eq!(lan.len(), MAX_PENDING_LAN_CANDIDATES);
        assert!(
            lan.pairs
                .iter()
                .any(|p| p.node == *configured_id.node_addr())
        );
    }

    #[test]
    fn a_second_address_for_the_same_npub_does_not_displace_the_first() {
        let honest = fresh();
        let a1: SocketAddr = "192.168.1.10:2121".parse().unwrap();
        let a2: SocketAddr = "192.168.1.66:2121".parse().unwrap();
        let mut sim = Sim::new(5);
        // The node's dials never complete, so every address of it is tried.
        sim.invented.insert(*honest.node_addr());
        sim.tick(
            0,
            vec![
                pair(honest, "192.168.1.10:2121"),
                pair(honest, "192.168.1.66:2121"),
            ],
        );
        for tick in 1..=61u64 {
            sim.tick(tick, Vec::new());
        }
        let tried: Vec<SocketAddr> = sim
            .dials
            .iter()
            .filter(|d| d.1 == *honest.node_addr())
            .map(|d| d.2)
            .collect();
        assert!(tried.iter().take(2).any(|a| *a == a1), "tried {tried:?}");
        assert!(tried.contains(&a2), "tried {tried:?}");
    }

    #[test]
    fn a_node_holds_at_most_four_pending_addresses_and_keeps_the_first_seen() {
        let mut lan = PendingLan::default();
        let mut rng = StdRng::seed_from_u64(6);
        let node = fresh();
        for i in 1..=4 {
            let held = lan.offer(
                pair(node, &format!("192.168.1.{i}:1")),
                &none(),
                0,
                &mut rng,
            );
            assert!(matches!(held, LanOffer::Held));
        }
        let fifth = lan.offer(pair(node, "192.168.1.5:1"), &none(), 0, &mut rng);
        assert!(matches!(fifth, LanOffer::RefusedPerNode));
        let held: Vec<String> = lan.pairs.iter().map(|p| p.addr.to_string()).collect();
        assert_eq!(
            held,
            [
                "192.168.1.1:1",
                "192.168.1.2:1",
                "192.168.1.3:1",
                "192.168.1.4:1"
            ]
        );
    }

    #[test]
    fn pending_lan_candidates_expire_after_ten_minutes() {
        let mut lan = PendingLan::default();
        let mut rng = StdRng::seed_from_u64(7);
        lan.offer(pair(fresh(), "192.168.1.1:1"), &none(), 1_000, &mut rng);
        lan.expire(1_000 + 599_999);
        assert_eq!(lan.len(), 1);
        lan.expire(1_000 + 600_000);
        assert!(lan.is_empty());
    }

    #[test]
    fn the_lan_set_full_warning_fires_once_and_releases_after_a_minute_below_the_bound() {
        let mut lan = PendingLan::default();
        let mut rng = StdRng::seed_from_u64(8);
        for i in 0..MAX_PENDING_LAN_CANDIDATES {
            lan.offer(
                pair(fresh(), &format!("192.168.1.{}:1", i + 1)),
                &none(),
                0,
                &mut rng,
            );
        }
        let first = lan.offer(pair(fresh(), "192.168.1.200:1"), &none(), 0, &mut rng);
        assert!(matches!(
            first,
            LanOffer::Replaced {
                first_at_bound: true,
                ..
            }
        ));
        let second = lan.offer(pair(fresh(), "192.168.1.201:1"), &none(), 0, &mut rng);
        assert!(matches!(
            second,
            LanOffer::Replaced {
                first_at_bound: false,
                ..
            }
        ));
        let everyone: HashSet<NodeAddr> = lan.pairs.iter().map(|p| p.node).collect();
        let refused = lan.offer(pair(fresh(), "192.168.1.202:1"), &everyone, 0, &mut rng);
        assert!(matches!(
            refused,
            LanOffer::Refused {
                first_at_bound: false
            }
        ));

        let some: HashSet<NodeAddr> = lan.pairs.iter().take(4).map(|p| p.node).collect();
        lan.prune_connected(&some);
        let t = 1_000;
        assert_eq!(lan.expire(t), None);
        assert_eq!(lan.expire(t + 59_999), None);
        assert_eq!(lan.expire(t + 60_000), Some(3));
        assert!(!lan.is_latched());
    }

    #[test]
    fn a_pair_follows_the_configured_set_at_ordering_time() {
        let mut lan = PendingLan::default();
        let mut rng = StdRng::seed_from_u64(9);
        let p = fresh();
        let q = fresh();
        for i in 0..4 {
            lan.offer(
                pair(fresh(), &format!("192.168.1.{}:1", i + 1)),
                &none(),
                0,
                &mut rng,
            );
        }
        lan.offer(pair(p, "192.168.1.50:1"), &none(), 0, &mut rng);
        lan.offer(pair(q, "192.168.1.51:1"), &none(), 0, &mut rng);

        let joined: HashSet<NodeAddr> = [*p.node_addr()].into_iter().collect();
        assert_eq!(lan.ordered(&joined, &mut rng)[0].node, *p.node_addr());

        let moved: HashSet<NodeAddr> = [*q.node_addr()].into_iter().collect();
        let order = lan.ordered(&moved, &mut rng);
        assert_eq!(order[0].node, *q.node_addr());
        assert_ne!(
            order[1].node,
            *p.node_addr(),
            "p keeps no place once it leaves"
        );
        assert_eq!(order.len(), 6);
    }

    #[test]
    fn lan_dial_targets_are_judged_against_this_nodes_links() {
        let prefix = |text: &str, len: u8| on_one(&[(text, len)]);
        let at = |text: &str| -> SocketAddr { text.parse().unwrap() };
        let empty = OnLinkPrefixes::default();
        assert!(lan_target_on_link(at("[fe80::1%3]:2121"), &[3], &empty));
        assert!(!lan_target_on_link(at("[fe80::1]:2121"), &[], &empty));
        assert!(lan_target_on_link(
            at("[fd00::5]:2121"),
            &[1],
            &prefix("fd00::", 64)
        ));
        assert!(!lan_target_on_link(
            at("[fd00::5]:2121"),
            &[1],
            &prefix("fd01::", 64)
        ));
        assert!(lan_target_on_link(
            at("192.168.1.7:2121"),
            &[1],
            &prefix("192.168.1.0", 24)
        ));
        assert!(!lan_target_on_link(
            at("192.168.1.7:2121"),
            &[1],
            &prefix("192.168.2.0", 24)
        ));
        assert!(lan_target_on_link(
            at("[::ffff:192.168.1.7]:2121"),
            &[1],
            &prefix("192.168.1.0", 24)
        ));
        assert!(
            !lan_target_on_link(at("192.168.1.7:2121"), &[], &prefix("192.168.1.0", 24)),
            "no arrival interface known"
        );
    }

    /// A sender on one link cannot aim dials into the node's other networks:
    /// an advert that arrived on the LAN interface naming an address in the
    /// prefix of a VPN or a container bridge on the same node is refused.
    #[test]
    fn an_advert_naming_another_interfaces_prefix_is_not_on_link() {
        let at = |text: &str| -> SocketAddr { text.parse().unwrap() };
        let ip = |text: &str| -> std::net::IpAddr { text.parse().unwrap() };
        let node = OnLinkPrefixes::from_indexed([
            (ip("192.168.1.10"), 24, Some(2)),
            (ip("10.8.0.2"), 24, Some(3)),
            (ip("172.17.0.1"), 16, Some(4)),
        ]);
        assert!(
            !lan_target_on_link(at("10.8.0.5:2121"), &[2], &node),
            "VPN host accepted"
        );
        assert!(
            !lan_target_on_link(at("172.17.0.9:2121"), &[2], &node),
            "container host accepted"
        );
        // Control: the same advert's address on the arrival link is dialled,
        // and so is the VPN address when the advert arrived over the VPN.
        assert!(lan_target_on_link(at("192.168.1.7:2121"), &[2], &node));
        assert!(lan_target_on_link(at("10.8.0.5:2121"), &[3], &node));
    }

    /// Unconfigured pairs for many nodes at one address, as forged npubs
    /// sharing a FIPS node's host name produce, are listed at most two
    /// nodes at a time, counting nodes already in flight there; pairs at
    /// other addresses and configured pairs are not held back.
    #[test]
    fn ordered_lists_at_most_two_unconfigured_nodes_per_address() {
        let mut lan = PendingLan::default();
        let mut rng = StdRng::seed_from_u64(11);
        let target: IpAddr = "192.168.1.5".parse().unwrap();
        for port in 1..=10 {
            lan.offer(
                pair(fresh(), &format!("192.168.1.5:{port}")),
                &none(),
                0,
                &mut rng,
            );
        }
        let configured_id = fresh();
        let configured: HashSet<NodeAddr> = [*configured_id.node_addr()].into_iter().collect();
        lan.offer(
            pair(configured_id, "192.168.1.5:99"),
            &configured,
            0,
            &mut rng,
        );
        for i in 1..=3 {
            lan.offer(
                pair(fresh(), &format!("192.168.1.{}:1", 10 + i)),
                &none(),
                0,
                &mut rng,
            );
        }
        let at_target = |order: &[&PendingPair]| {
            order
                .iter()
                .filter(|p| p.addr.ip() == target && p.node != *configured_id.node_addr())
                .count()
        };

        let order = lan.ordered(&configured, &mut rng);
        assert_eq!(order[0].node, *configured_id.node_addr());
        assert_eq!(at_target(&order), MAX_LAN_DIALS_PER_ADDR);
        assert_eq!(order.len(), 1 + MAX_LAN_DIALS_PER_ADDR + 3);

        // One node is now in flight at the target, dialled at another port.
        let first = order
            .iter()
            .find(|p| p.addr.ip() == target && p.node != *configured_id.node_addr())
            .map(|p| (p.node, p.addr))
            .unwrap();
        lan.take(&first.0, first.1);
        lan.note_dialed(first.0, "192.168.1.5:7000".parse().unwrap());
        let order = lan.ordered(&configured, &mut rng);
        assert_eq!(at_target(&order), MAX_LAN_DIALS_PER_ADDR - 1);
        assert_eq!(order.len(), 1 + (MAX_LAN_DIALS_PER_ADDR - 1) + 3);

        // The bound reads the address in its canonical form.
        lan.note_dialed(
            *fresh().node_addr(),
            "[::ffff:192.168.1.5]:1".parse().unwrap(),
        );
        assert_eq!(at_target(&lan.ordered(&configured, &mut rng)), 0);
    }

    #[test]
    fn a_held_lan_pair_whose_link_went_away_is_not_dialled() {
        let mut lan = PendingLan::default();
        let mut rng = StdRng::seed_from_u64(10);
        lan.offer(pair(fresh(), "192.168.1.7:2121"), &none(), 0, &mut rng);
        let gone = on_one(&[("192.168.2.0", 24)]);
        assert_eq!(lan.retain_on_link(&gone), 1);
        assert!(lan.is_empty());
    }
}
