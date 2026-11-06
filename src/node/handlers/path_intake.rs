//! Path candidate intake (multipath v1 draft, Section 5.4, the note): what
//! the node's sources say about where a linked peer may be reachable,
//! turned into the `Candidate` and `Unlisted` inputs of the peer's path
//! machine.
//!
//! [`Listings`] holds, for each linked peer and each feed, the pairs that
//! feed lists. A feed that reports one pair at a time (a beacon) gives a
//! `Candidate` when it reports a pair it did not list and nothing when it
//! reports one again, and gives `Unlisted` once a pair has gone unreported
//! for the feed's silence. A feed that gives its whole list at once
//! (configuration, a Nostr advert) gives a `Candidate` for each pair new to
//! the list and `Unlisted` for each pair gone from it. The core needs that
//! `Unlisted`: it holds back a
//! pair whose path it gave up on until a source reports the pair afresh
//! (draft Section 5.6, "No scheduled retry"), and a report from a source
//! that already lists the pair is a repeat, not fresh, so without it a
//! source that still hears the pair could never offer it again.
//!
//! Every intake step runs only with multipath enabled; with it disabled
//! the node reports nothing and lists nothing.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use fips_core::proto::path::{Input, Source};

use crate::config::{PeerAddress, PeerConfig};
use crate::node::Node;
use crate::transport::{TransportAddr, TransportHandle, TransportId};
use crate::{NodeAddr, PeerIdentity};

/// How long a beacon may go unheard before its pair is unlisted: four
/// default beacon intervals (30 s), so one or two lost beacons do not
/// unlist a pair the peer still announces.
pub(in crate::node) const BEACON_SILENCE: Duration = Duration::from_secs(120);

/// How long a pair the peer is heard from on no path may go unheard
/// before it is unlisted. A pair the link admits is then heard on its path
/// and no longer reported, so this only bounds how long a pair the peer
/// has stopped sending from stays listed.
pub(in crate::node) const HEARD_SILENCE: Duration = Duration::from_secs(120);

/// The most pairs one feed lists for one peer. Beacons are not
/// authenticated, so a forged one could otherwise grow a peer's listing
/// without bound; the core's table holds only eight.
pub(in crate::node) const LISTED_MAX: usize = 16;

/// A source of candidates as the node hears it. Feeds that differ in how
/// they report, or in how long a silence means a pair is gone, are kept
/// apart even where the core counts them as one [`Source`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) enum Feed {
    /// Beacons heard by a transport's discovery: local discovery.
    Beacon,
    /// The peer's configured addresses, as a whole list.
    Config,
    /// The direct endpoints of the peer's cached Nostr advert, as a whole
    /// list.
    Nostr,
    /// mDNS adverts: local discovery, one address at a time. mdns-sd
    /// reports a service again only when its records change, not while
    /// they stay current, so silence says nothing and an mDNS listing
    /// lasts until the link goes or its machine starts again.
    Mdns,
    /// Addresses the peer is heard from on no path: authentic frames, not
    /// path messages, from a pair the link holds no path at.
    Heard,
}

/// The number of feeds.
const FEEDS: usize = 5;

impl Feed {
    /// Every feed, in index order.
    const ALL: [Self; FEEDS] = [
        Self::Beacon,
        Self::Config,
        Self::Nostr,
        Self::Mdns,
        Self::Heard,
    ];

    /// The feed's slot in a peer's listing.
    fn index(self) -> usize {
        match self {
            Self::Beacon => 0,
            Self::Config => 1,
            Self::Nostr => 2,
            Self::Mdns => 3,
            Self::Heard => 4,
        }
    }

    /// The core source the feed reports as.
    pub(in crate::node) fn source(self) -> Source {
        match self {
            Self::Beacon | Self::Mdns => Source::Discovery,
            Self::Config => Source::Config,
            Self::Nostr => Source::Nostr,
            Self::Heard => Source::Heard,
        }
    }

    /// How long a pair may go unreported before the feed no longer lists
    /// it; `None` for a feed that gives its whole list, which says so
    /// itself, and for mDNS, whose silence means nothing.
    fn silence(self) -> Option<Duration> {
        match self {
            Self::Beacon => Some(BEACON_SILENCE),
            Self::Heard => Some(HEARD_SILENCE),
            Self::Config | Self::Nostr | Self::Mdns => None,
        }
    }
}

/// One pair a feed lists, with when the feed last reported it, in
/// [`crate::time::mono_ms`] milliseconds.
#[derive(Clone, Debug)]
struct Listed {
    /// The local transport.
    transport: TransportId,
    /// The peer's address on it.
    addr: TransportAddr,
    /// When the feed last reported the pair.
    at: u64,
}

/// What every feed lists for one peer.
type PeerListing = [Vec<Listed>; FEEDS];

/// The pairs each feed lists for each linked peer.
#[derive(Debug, Default)]
pub(in crate::node) struct Listings {
    /// Each peer's listing, by feed.
    peers: HashMap<NodeAddr, PeerListing>,
}

impl Listings {
    /// `feed` reports (`transport`, `addr`) for `peer` at `now`. A pair the
    /// feed did not list gives a `Candidate`, and if the feed then lists
    /// more than [`LISTED_MAX`] pairs for the peer, its least recently
    /// reported one is unlisted. A pair it lists already only has its
    /// instant refreshed, and gives nothing.
    pub(in crate::node) fn report(
        &mut self,
        peer: NodeAddr,
        feed: Feed,
        transport: TransportId,
        addr: TransportAddr,
        now: u64,
    ) -> Vec<Input> {
        let listing = self.peers.entry(peer).or_default();
        let list = &mut listing[feed.index()];
        if let Some(known) = list
            .iter_mut()
            .find(|l| l.transport == transport && l.addr == addr)
        {
            known.at = now;
            return Vec::new();
        }
        let mut out = Vec::new();
        if !elsewhere(listing, feed, transport, &addr) {
            out.push(Input::Candidate {
                transport,
                addr: addr.clone(),
                source: feed.source(),
            });
        }
        let list = &mut listing[feed.index()];
        list.push(Listed {
            transport,
            addr,
            at: now,
        });
        if list.len() > LISTED_MAX
            && let Some(oldest) = list
                .iter()
                .enumerate()
                .min_by_key(|(_, l)| l.at)
                .map(|(i, _)| i)
        {
            let gone = list.remove(oldest);
            out.extend(unlisted(listing, feed, gone));
        }
        out
    }

    /// `feed` gives its whole list for `peer` at `now`: `pairs`, of which
    /// the first [`LISTED_MAX`] distinct ones are kept. Each pair it did
    /// not list before gives a `Candidate`, and each it no longer lists an
    /// `Unlisted`, the `Unlisted` inputs first; an unchanged list gives
    /// nothing.
    pub(in crate::node) fn list(
        &mut self,
        peer: NodeAddr,
        feed: Feed,
        pairs: &[(TransportId, TransportAddr)],
        now: u64,
    ) -> Vec<Input> {
        if pairs.is_empty() && !self.peers.contains_key(&peer) {
            return Vec::new();
        }
        let listing = self.peers.entry(peer).or_default();
        let old = std::mem::take(&mut listing[feed.index()]);
        let mut new: Vec<Listed> = Vec::new();
        for (transport, addr) in pairs {
            if new.len() == LISTED_MAX {
                break;
            }
            if !new
                .iter()
                .any(|l| l.transport == *transport && l.addr == *addr)
            {
                new.push(Listed {
                    transport: *transport,
                    addr: addr.clone(),
                    at: now,
                });
            }
        }
        let fresh: Vec<(TransportId, TransportAddr)> = new
            .iter()
            .filter(|l| {
                !old.iter()
                    .any(|o| o.transport == l.transport && o.addr == l.addr)
            })
            .map(|l| (l.transport, l.addr.clone()))
            .collect();
        let gone: Vec<Listed> = old
            .into_iter()
            .filter(|o| {
                !new.iter()
                    .any(|l| l.transport == o.transport && l.addr == o.addr)
            })
            .collect();
        listing[feed.index()] = new;
        let mut out: Vec<Input> = gone
            .into_iter()
            .filter_map(|l| unlisted(listing, feed, l))
            .collect();
        for (transport, addr) in fresh {
            if !elsewhere(listing, feed, transport, &addr) {
                out.push(Input::Candidate {
                    transport,
                    addr,
                    source: feed.source(),
                });
            }
        }
        out
    }

    /// Unlist every pair a feed has not reported for its silence at `now`,
    /// and drop every peer `linked` no longer holds, whose machine is gone
    /// with its link. Returns the `Unlisted` inputs, with their peers.
    pub(in crate::node) fn expire(
        &mut self,
        now: u64,
        linked: impl Fn(&NodeAddr) -> bool,
    ) -> Vec<(NodeAddr, Input)> {
        self.peers.retain(|peer, _| linked(peer));
        let mut out = Vec::new();
        for (peer, listing) in &mut self.peers {
            for feed in Feed::ALL {
                let Some(silence) = feed.silence() else {
                    continue;
                };
                let silence = u64::try_from(silence.as_millis()).unwrap_or(u64::MAX);
                let list = &mut listing[feed.index()];
                let (gone, kept) = std::mem::take(list)
                    .into_iter()
                    .partition::<Vec<_>, _>(|l| now.saturating_sub(l.at) >= silence);
                *list = kept;
                for l in gone {
                    out.extend(unlisted(listing, feed, l).map(|input| (*peer, input)));
                }
            }
        }
        out
    }

    /// Drop everything listed for `peer`, whose path machine has started
    /// again with an empty candidate table: the next report of each pair
    /// is then a `Candidate` for the new machine.
    pub(in crate::node) fn forget(&mut self, peer: &NodeAddr) {
        self.peers.remove(peer);
    }

    /// The pairs `feed` lists for `peer`, for tests.
    #[cfg(test)]
    pub(in crate::node) fn listed(
        &self,
        peer: &NodeAddr,
        feed: Feed,
    ) -> Vec<(TransportId, TransportAddr)> {
        self.peers.get(peer).map_or_else(Vec::new, |listing| {
            listing[feed.index()]
                .iter()
                .map(|l| (l.transport, l.addr.clone()))
                .collect()
        })
    }
}

/// Whether a feed other than `feed` that reports as the same core source
/// lists (`transport`, `addr`) in `listing`: the core then lists the pair
/// for that source already, and must not be told it is new or gone.
fn elsewhere(
    listing: &PeerListing,
    feed: Feed,
    transport: TransportId,
    addr: &TransportAddr,
) -> bool {
    Feed::ALL
        .into_iter()
        .filter(|other| *other != feed && other.source() == feed.source())
        .any(|other| {
            listing[other.index()]
                .iter()
                .any(|l| l.transport == transport && l.addr == *addr)
        })
}

/// The `Unlisted` input for `gone`, which `feed` no longer lists, unless
/// another feed of the same core source still lists it.
fn unlisted(listing: &PeerListing, feed: Feed, gone: Listed) -> Option<Input> {
    (!elsewhere(listing, feed, gone.transport, &gone.addr)).then_some(Input::Unlisted {
        transport: gone.transport,
        addr: gone.addr,
        source: feed.source(),
    })
}

/// A UDP transport an mDNS advert may be attributed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) struct UdpLane {
    /// The transport.
    pub(in crate::node) id: TransportId,
    /// The OS index of the interface it is bound to, if it is bound to one.
    pub(in crate::node) ifindex: Option<u32>,
    /// Its local address.
    pub(in crate::node) local: SocketAddr,
}

/// The UDP transport an mDNS advert of `addr` that arrived on `interfaces`
/// is a candidate on: among `lanes` of `addr`'s address family, the lowest
/// id bound to one of those interfaces, or else the lowest id, the one a
/// dial of the address takes. With two instances bound to two interfaces,
/// the advert's own interface is the one its address is reachable on.
pub(in crate::node) fn mdns_lane(
    lanes: &[UdpLane],
    addr: SocketAddr,
    interfaces: &[u32],
) -> Option<TransportId> {
    let family = lanes.iter().filter(|l| l.local.is_ipv4() == addr.is_ipv4());
    family
        .clone()
        .filter(|l| l.ifindex.is_some_and(|i| interfaces.contains(&i)))
        .map(|l| l.id)
        .min_by_key(|id| id.as_u32())
        .or_else(|| family.map(|l| l.id).min_by_key(|id| id.as_u32()))
}

/// The OS index of the interface the UDP transport `handle` is bound to,
/// if it names one that exists now. Only unix maps a name to an index.
fn bound_index(handle: &TransportHandle) -> Option<u32> {
    let TransportHandle::Udp(udp) = handle else {
        return None;
    };
    let name = udp.interface()?;
    #[cfg(unix)]
    {
        let name = std::ffi::CString::new(name).ok()?;
        // SAFETY: `name` is a valid NUL-terminated string for the call's
        // duration.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        (index != 0).then_some(index)
    }
    #[cfg(not(unix))]
    {
        let _ = name;
        None
    }
}

impl Node {
    /// The UDP transports an mDNS advert may be attributed to: those a dial
    /// of a LAN address may take, operational and not carrying a NAT
    /// traversal, with their bound interfaces.
    pub(in crate::node) fn udp_lanes(&self) -> Vec<UdpLane> {
        self.transports
            .iter()
            .filter(|(id, handle)| {
                handle.transport_type().name == "udp"
                    && handle.is_operational()
                    && !self.supervisor.nostr_rendezvous.is_bootstrap_transport(id)
            })
            .filter_map(|(id, handle)| {
                Some(UdpLane {
                    id: *id,
                    ifindex: bound_index(handle),
                    local: handle.local_addr()?,
                })
            })
            .collect()
    }

    /// `feed` reports that the linked peer `peer` may be reachable at
    /// (`transport`, `addr`): step what the report gives into the peer's
    /// path machine. Nothing is listed or stepped with multipath disabled,
    /// or for a peer the node does not hold.
    pub(in crate::node) async fn intake(
        &mut self,
        peer: &NodeAddr,
        feed: Feed,
        transport: TransportId,
        addr: TransportAddr,
    ) {
        if !self.config().node.path.enabled || !self.peers.contains_key(peer) {
            return;
        }
        let now = crate::time::mono_ms();
        let inputs = self
            .paths
            .listings
            .report(*peer, feed, transport, addr, now);
        for input in inputs {
            self.step_path(peer, input).await;
        }
    }

    /// Unlist what the feeds have gone silent on and drop the listings of
    /// peers no longer held, stepping each `Unlisted` into its peer's
    /// machine. Runs on the discovery tick.
    pub(in crate::node) async fn intake_expire(&mut self) {
        if !self.config().node.path.enabled {
            return;
        }
        let now = crate::time::mono_ms();
        let peers = &self.peers;
        let gone = self
            .paths
            .listings
            .expire(now, |peer| peers.contains_key(peer));
        for (peer, input) in gone {
            self.step_path(&peer, input).await;
        }
    }

    /// Read the facts again: step every linked peer's path machine with a
    /// poll, so a change in the facts its rules read (the peer ACL, a
    /// transport started or adopted) takes effect within one discovery
    /// tick, whatever source fed its candidates. The capability gate and a
    /// Dead path's cadence then read the facts as they are now (multipath
    /// v1 draft, Section 5.5), and the poll offers again each candidate a
    /// rule refused, so an ACL reload or an added transport admits it
    /// without a fresh report of it. A poll is used rather than a step at each
    /// place a fact changes, since those are several and a missed one is
    /// silent, while a poll before a machine's next wake, with the facts
    /// unchanged, does nothing. Runs on the discovery tick; nothing is
    /// stepped with multipath disabled.
    pub(in crate::node) async fn reread(&mut self) {
        if !self.config().node.path.enabled {
            return;
        }
        let linked: Vec<NodeAddr> = self.peers.keys().copied().collect();
        for peer in linked {
            self.step_path(&peer, Input::Poll).await;
        }
    }

    /// The path machine of the link to `peer` has started again with an
    /// empty candidate table, at a promotion or a won crossed handshake:
    /// forget what the feeds listed for the old one, so each feed's next
    /// report offers its pairs to the new one, and offer the peer's
    /// configured and advertised addresses to it now.
    pub(in crate::node) async fn paths_renewed(&mut self, peer: &NodeAddr) {
        if !self.config().node.path.enabled {
            return;
        }
        self.paths.listings.forget(peer);
        let config = self.config_of(peer);
        self.offer_configured(peer, config.as_ref()).await;
    }

    /// Offer every linked peer's configured addresses, and the direct
    /// endpoints of its cached Nostr advert, as whole lists: a pair new to
    /// a list is a candidate, and one gone from it is unlisted. A linked
    /// peer the configuration does not name lists none. Runs on the
    /// discovery tick and after the configured peers change.
    pub(in crate::node) async fn offer_configs(&mut self) {
        if !self.config().node.path.enabled {
            return;
        }
        let configs: HashMap<NodeAddr, PeerConfig> = self
            .config()
            .peers()
            .iter()
            .filter_map(|pc| {
                PeerIdentity::from_npub(&pc.npub)
                    .ok()
                    .map(|id| (*id.node_addr(), pc.clone()))
            })
            .collect();
        let linked: Vec<NodeAddr> = self.peers.keys().copied().collect();
        for peer in linked {
            self.offer_configured(&peer, configs.get(&peer)).await;
        }
    }

    /// `connect` named `address` for the linked peer `peer`, whose link is
    /// live: hold the address as a path candidate from the operator's
    /// request rather than dial it (multipath v1 draft, Section 5.4). Every
    /// request is fresh, so it also offers again a pair given up on. For a
    /// peer not known to be capable the candidate opens capability probing
    /// and nothing more. Returns, for a capable peer, whether the pair was
    /// already held as a path; `None` for a peer not known to be capable,
    /// whose reply stays the one a node without multipath gives, and for an
    /// address that resolves to no pair, which is left to the dialler.
    pub(in crate::node) async fn connect_candidate(
        &mut self,
        peer: &NodeAddr,
        address: &PeerAddress,
    ) -> Option<bool> {
        let (transport, addr) = self
            .pairs_of(std::slice::from_ref(address))
            .into_iter()
            .next()?;
        let held = self.peers.get(peer)?;
        let capable = held.bundle().is_some_and(|b| b.capable());
        let path = !matches!(held.path_match(transport, &addr), crate::peer::Match::None);
        let input = Input::Candidate {
            transport,
            addr,
            source: Source::Request,
        };
        self.step_path(peer, input).await;
        capable.then_some(path)
    }

    /// The configuration's entry for `peer`, if it names the peer.
    fn config_of(&self, peer: &NodeAddr) -> Option<PeerConfig> {
        self.config()
            .peers()
            .iter()
            .find(|pc| PeerIdentity::from_npub(&pc.npub).is_ok_and(|id| id.node_addr() == peer))
            .cloned()
    }

    /// List `config`'s addresses for the linked peer `peer` as the
    /// configuration feed, and its cached advert's direct endpoints as the
    /// Nostr feed, stepping what changes into the peer's path machine.
    async fn offer_configured(&mut self, peer: &NodeAddr, config: Option<&PeerConfig>) {
        if !self.peers.contains_key(peer) {
            return;
        }
        let (configured, advertised) = match config {
            Some(config) => {
                let configured: Vec<PeerAddress> = config
                    .addresses_by_priority()
                    .into_iter()
                    .cloned()
                    .collect();
                let advertised = self.supervisor.nostr_rendezvous.cached_addresses(
                    config,
                    &configured,
                    &self.config().node.rendezvous.nostr,
                    Self::now_ms(),
                );
                (self.pairs_of(&configured), self.pairs_of(&advertised))
            }
            None => (Vec::new(), Vec::new()),
        };
        let now = crate::time::mono_ms();
        for (feed, pairs) in [(Feed::Config, configured), (Feed::Nostr, advertised)] {
            let inputs = self.paths.listings.list(*peer, feed, &pairs, now);
            for input in inputs {
                self.step_path(peer, input).await;
            }
        }
    }

    /// The pairs `addresses` resolve to as the dialler resolves them, in
    /// order. Left out: the `nat` pseudo-address, which names a NAT
    /// traversal rather than an endpoint (a node discards a traversal to a
    /// peer it is already linked with, FRC-1601 Section 6.4), and a UDP or
    /// TCP address that is a host name rather than a socket address, which
    /// would name a pair the link never holds (its paths hold the numeric
    /// address the peer is heard from) and so open a second path to the
    /// same endpoint.
    fn pairs_of(&self, addresses: &[PeerAddress]) -> Vec<(TransportId, TransportAddr)> {
        addresses
            .iter()
            .filter(|addr| {
                let kind = addr.spec().kind;
                !(kind == "udp" || kind == "tcp") || addr.addr.parse::<SocketAddr>().is_ok()
            })
            .filter_map(|addr| self.resolve_peer_address(addr))
            .collect()
    }
}
