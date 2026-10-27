//! The node's end of the link to the IPv6 adapter.
//!
//! The adapter attaches once per start, before its device opens, and the
//! node answers in line: who it is, the payload limit it last published, the
//! replay of every per-peer limit and every routable key the adapter asked
//! for, and the end of the replay. From then on the node pushes the
//! node-wide limit whenever it moves, each per-peer change as the path MTU
//! map makes it, and each key as the identity cache learns or forgets it.
//! The link ends at the teardown step that drops the packet channels.
//!
//! Up the link come the adapter's datagrams, each the host's packet with its
//! header compressed and the key of its destination, and the keys its DNS
//! responder handed to the host. The node sends a datagram as the TUN path
//! always has: checked against the node-wide limit, resolved through the
//! identity cache, checked against an established session's path MTU, then
//! sent, queued or refused. A refusal goes back to the adapter in line.

use std::sync::atomic::{AtomicU16, Ordering};

use secp256k1::PublicKey;

use crate::NodeAddr;
use crate::config::{ConfigError, Grant, Principal};
use crate::ipv6tun::link::{self, Attach, Datagram, FromMesh, PeerKey, Refusal};
use crate::ipv6tun::mtu::mss_ceiling;
use crate::ipv6tun::tun::IPV6_MIN_MTU;
use crate::node::path_mtu::payload_limit;
use crate::node::{Node, NodeError};

/// What the node has published of its node-wide limit, and the ceiling it
/// last logged at a transport change.
pub(crate) struct NodeMtuFeed {
    /// The payload limit last pushed, or the one `Attached` will carry.
    published: AtomicU16,
    /// The TCP MSS ceiling last logged at a transport change.
    logged: AtomicU16,
}

impl NodeMtuFeed {
    /// Both values at the IPv6 minimum, which is what `transport_mtu()`
    /// falls back to when nothing is bound.
    pub(crate) fn new() -> Self {
        Self {
            published: AtomicU16::new(payload_limit(IPV6_MIN_MTU)),
            logged: AtomicU16::new(mss_ceiling(IPV6_MIN_MTU)),
        }
    }

    /// Swap in the TCP MSS ceiling `ceiling`, returning the one last logged.
    pub(crate) fn swap_logged(&self, ceiling: u16) -> u16 {
        self.logged.swap(ceiling, Ordering::Relaxed)
    }

    /// The TCP MSS ceiling last logged.
    #[cfg(test)]
    pub(crate) fn logged(&self) -> u16 {
        self.logged.load(Ordering::Relaxed)
    }
}

/// Whether the adapter's grant among `grants` covers the port `request`
/// asks for. The port is all a grant can withhold from the adapter: its
/// identity feed and learn request are kept whoever holds port 256.
fn granted(request: &Attach, grants: &[Grant]) -> Result<(), NodeError> {
    let Some(port) = request.port else {
        return Ok(());
    };
    let held = grants
        .iter()
        .any(|g| g.principal == Principal::Adapter && g.ports.contains(&port));
    if held {
        return Ok(());
    }
    Err(NodeError::Config(ConfigError::Validation(format!(
        "the IPv6 adapter needs port {port} for the TUN, but node.native_api.grants \
         gives it to another principal"
    ))))
}

impl Node {
    /// Attach the IPv6 adapter: take its request, answer it, and hand it its
    /// end of the link with the answer already queued.
    ///
    /// Runs inside `start()`, where the receive loop is not yet running, so
    /// the adapter has the whole reply before its device opens.
    pub(in crate::node) fn attach_host(&mut self) {
        let request = self.supervisor.ipv6tun.attach_request();
        self.attach_with(request);
    }

    /// Refuse the adapter's attach if it would serve a port the grants in
    /// force do not give it: an app-owned TUN on a node whose configuration
    /// gives port 256 to a user, which validation cannot see because the
    /// embedder installs the TUN after the configuration is loaded.
    /// `start()` calls this before [`Node::attach_host`], so a refused
    /// adapter is never attached.
    pub(in crate::node) fn check_attach(&self) -> Result<(), NodeError> {
        let request = self.supervisor.ipv6tun.attach_request();
        granted(&request, &self.config().node.native_api.effective_grants())
    }

    /// Answer the attach `request`.
    fn attach_with(&mut self, request: Attach) {
        let Attach { port, feeds } = request;
        // `start()` checked the request against the grants before calling
        // the attach.
        debug_assert!(
            granted(&request, &self.config().node.native_api.effective_grants()).is_ok(),
            "the adapter attached to a port the grants do not give it"
        );
        debug_assert!(port.is_none_or(|p| p == link::IPV6_PORT));
        let buffers = &self.config().node.buffers;
        let (mesh_link, host_link, datagrams, learned) =
            link::pair(buffers.tun_channel, buffers.dns_channel);
        host_link.send(FromMesh::Attached {
            node: PeerKey::from_xonly(&self.identity().pubkey()),
            payload_limit: self.node_mtu.published.load(Ordering::Relaxed),
        });
        if feeds.path_mtu {
            self.path_mtu_lookup.attach(host_link.clone());
        }
        if feeds.identity {
            // A session that holds its peer's key answers for the cache, so
            // the adapter is told of those keys too.
            let held: Vec<_> = self
                .sessions
                .iter()
                .filter_map(|(addr, entry)| entry.key().map(|key| (key, *addr)))
                .collect();
            self.identity_cache.attach(host_link.clone(), held);
        }
        host_link.send(FromMesh::Synced);
        self.supervisor.host_link = Some(host_link);
        self.supervisor.datagram_rx = Some(datagrams);
        self.supervisor.learned_rx = Some(learned);
        self.supervisor.ipv6tun.attached(mesh_link, feeds);
    }

    /// End the link and wait for the adapter to apply what was still queued
    /// on it: its receiver closes once both senders go.
    pub(in crate::node) async fn detach_host(&mut self) {
        self.supervisor.host_link = None;
        self.supervisor.datagram_rx = None;
        self.supervisor.learned_rx = None;
        self.identity_cache.detach();
        self.path_mtu_lookup.detach();
        self.supervisor.ipv6tun.detached().await;
    }

    /// Push the node-wide payload limit if it differs from the last one
    /// published, and return it.
    ///
    /// Called on every tick as well as at each transport change, so the
    /// adapter's copy is at most one tick behind even where no transport
    /// change was seen.
    pub(in crate::node) fn publish_mtu(&self) -> u16 {
        let limit = self.native_max_payload();
        // Read first: this runs per datagram, and the limit rarely moves.
        if self.node_mtu.published.load(Ordering::Relaxed) != limit
            && self.node_mtu.published.swap(limit, Ordering::Relaxed) != limit
            && let Some(host_link) = &self.supervisor.host_link
        {
            host_link.send(FromMesh::NodeMtu {
                payload_limit: limit,
            });
        }
        limit
    }
}

/// The payload limit at which a session whose path MTU is `path_mtu`
/// refuses a payload of `len` bytes, or `None` if it carries it.
///
/// Only a path narrower than the node-wide `limit` refuses anything: the
/// node-wide check has already refused what is over that.
pub(in crate::node) fn path_refusal(len: usize, path_mtu: u16, limit: u16) -> Option<u16> {
    let path_limit = payload_limit(path_mtu);
    (path_limit < limit && len > usize::from(path_limit)).then_some(path_limit)
}

impl Node {
    /// Send, queue or refuse one of the adapter's datagrams, in the order
    /// the TUN path always has: the node-wide limit, the destination's
    /// identity, an established session's path MTU, then the session.
    ///
    /// The receive loop registers the keys the adapter's DNS responder
    /// reported before each datagram, so a key the host was handed before
    /// it sent the packet is already cached here.
    pub(in crate::node) async fn handle_datagram(&mut self, datagram: Datagram) {
        let Datagram { peer, payload } = datagram;

        // The node-wide limit, live. A push the adapter has not applied yet
        // leaves it judging by the last one.
        let limit = self.publish_mtu();
        if payload.len() > usize::from(limit) {
            self.refuse(Refusal::TooBig {
                peer,
                payload_limit: limit,
                payload,
            });
            return;
        }

        let Some((dest_addr, dest_pubkey)) = self.resolve_key(&peer) else {
            self.refuse(Refusal::NoRoute {
                peer,
                payloads: vec![payload],
            });
            return;
        };

        // The path MTU an established session has learned. The first
        // oversized packet is forwarded normally and triggers the
        // MtuExceeded signal; later ones are refused here, which the
        // adapter answers with Packet Too Big. Only a path narrower than the
        // node-wide limit refuses anything the limit above let through.
        if let Some(path_limit) = self
            .sessions
            .get(&dest_addr)
            .filter(|entry| entry.is_established())
            .and_then(|entry| entry.mmp())
            .and_then(|mmp| path_refusal(payload.len(), mmp.path_mtu.current_mtu(), limit))
        {
            self.refuse(Refusal::TooBig {
                peer,
                payload_limit: path_limit,
                payload,
            });
            return;
        }

        self.send_outbound(dest_addr, dest_pubkey, peer, payload)
            .await;
    }

    /// The node address and cached key of the destination the adapter named
    /// `peer`, through the identity cache and the sessions that answer for
    /// it: exactly the lookup the TUN path made by the packet's address
    /// prefix, which is the prefix of the node address `peer`'s key hashes
    /// to.
    ///
    /// The feed already holds that node address for every key the adapter
    /// was told of, so the hash is computed here only for a key it was not.
    fn resolve_key(&mut self, peer: &PeerKey) -> Option<(NodeAddr, PublicKey)> {
        let addr = self
            .identity_cache
            .address(peer)
            .unwrap_or_else(|| peer.addr());
        let prefix = addr.prefix();
        self.lookup_by_fips_prefix(&prefix)
    }

    /// Tell the adapter to forget each key the node can no longer route to.
    /// Called on every tick.
    pub(in crate::node) fn sweep_identities(&mut self) {
        let sessions = &self.sessions;
        self.identity_cache.sweep(|addr, key| {
            sessions
                .get(addr)
                .and_then(|entry| entry.key())
                .map(|k| PeerKey::from_xonly(&k))
                == Some(*key)
        });
        #[cfg(debug_assertions)]
        for (addr, entry) in &self.sessions {
            if let Some(key) = entry.key() {
                debug_assert!(
                    self.identity_cache.told(&PeerKey::from_xonly(&key)),
                    "the session to {addr} holds a key the adapter was never told of"
                );
            }
        }
    }

    /// Forward one IPv6 packet from the host as the adapter would, for tests
    /// written against the TUN path: run the adapter's host half on it, then
    /// handle the datagram it produces in line. A node no start has attached
    /// is attached first with the identity feed, and the node-wide limit is
    /// published, as the next tick would, so a packet to a destination the
    /// adapter cannot name is judged by the limit the node carries now.
    #[cfg(test)]
    pub(in crate::node) async fn handle_tun_outbound(&mut self, ipv6_packet: Vec<u8>) {
        if !self.supervisor.ipv6tun.is_attached() {
            self.attach_with(Attach {
                port: Some(link::IPV6_PORT),
                feeds: link::Feeds {
                    path_mtu: false,
                    identity: true,
                },
            });
        }
        self.publish_mtu();
        if let Some(datagram) = self.supervisor.ipv6tun.outbound(&ipv6_packet) {
            self.handle_datagram(datagram).await;
        }
    }
}
