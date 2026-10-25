//! The link between the IPv6 adapter and the mesh node.
//!
//! Everything the adapter learns from the node arrives here as an owned
//! message, and nothing the node holds is shared with the adapter's threads.
//! The adapter's end is [`MeshLink`], the node's end [`HostLink`]; only the
//! node's attach step builds the pair. The messages carry only integers,
//! flags, byte strings and [`PeerKey`]s: owned values with nothing of the
//! node's state behind them.
//!
//! A remote end is named by its x-only public key, never by a node address
//! or an `fd00::/8` prefix; the adapter derives addresses itself.
//!
//! Three channels carry the messages. Down, one unbounded channel of
//! [`FromMesh`] in the order the node sends them. Up, two bounded ones: the
//! adapter's datagrams, and the keys its DNS responder learned, kept apart
//! so that a burst of datagrams never holds a registration back. The node
//! answers a datagram it refuses with a [`Refusal`], handed to the adapter
//! in line where the refusal is decided, and hands it each datagram a peer
//! sent to the IPv6 port as a [`Deliver`], in line where it is received, so
//! the host sees deliveries and answers in the order the node made them.

use tokio::sync::mpsc::{
    Receiver, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel,
};

/// A peer named by the 32 bytes of its x-only public key: the identity
/// module's key type, which hashes and compares as bytes, as the node does
/// for every datagram, without a call into secp256k1.
pub(crate) use fips_core::identity::PeerKey;

/// The FSP port the IPv6 adapter's traffic uses.
pub(crate) const IPV6_PORT: u16 = 256;

/// Some peer's key, for a test that needs one but not a particular one.
#[cfg(test)]
pub(crate) fn any_key() -> PeerKey {
    PeerKey::from_xonly(&crate::Identity::generate().pubkey())
}

/// Which state feeds an attach asks the node to replay and keep pushing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Feeds {
    /// The per-peer path MTU feed: one [`FromMesh::PathMtu`] per entry at
    /// attach, then one per change.
    pub(crate) path_mtu: bool,
    /// The identity feed: one [`FromMesh::KnownKey`] per key the node can
    /// route to at attach, then one per key it learns and a
    /// [`FromMesh::ForgotKey`] once it can no longer route to one.
    pub(crate) identity: bool,
}

/// The adapter's request to attach to the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Attach {
    /// The FSP port the adapter serves, `Some(256)` while the TUN is enabled.
    pub(crate) port: Option<u16>,
    /// The state feeds the adapter wants.
    pub(crate) feeds: Feeds,
}

/// Everything the node sends the adapter, in the order it sends it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FromMesh {
    /// The reply to [`Attach`]: who the node is, and the payload limit it
    /// last published.
    Attached {
        /// The node's own key.
        node: PeerKey,
        /// The largest payload, in bytes, the node sends to any peer.
        payload_limit: u16,
    },
    /// The end of the state replayed after `Attached`.
    Synced,
    /// The node's payload limit changed.
    NodeMtu {
        /// The largest payload, in bytes, the node sends to any peer.
        payload_limit: u16,
    },
    /// The node learned or released a per-peer payload limit.
    PathMtu {
        /// The peer the limit applies to.
        peer: PeerKey,
        /// The limit in bytes, or `None` when the node released it.
        payload_limit: Option<u16>,
    },
    /// The node can route to this peer by its key.
    KnownKey {
        /// The peer.
        peer: PeerKey,
    },
    /// The node can no longer route to this peer.
    ForgotKey {
        /// The peer.
        peer: PeerKey,
        /// The number of the last [`Learned`] the node had handled when it
        /// decided this. A key the adapter has learned again since then is
        /// kept.
        learned: u64,
    },
}

/// A datagram from the host for the node to send to `peer` on the IPv6
/// port: the IPv6 packet with its header compressed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Datagram {
    /// The destination.
    pub(crate) peer: PeerKey,
    /// The compressed packet.
    pub(crate) payload: Vec<u8>,
}

/// A datagram a peer sent to the IPv6 port, for the adapter to hand the
/// host: the IPv6 packet with its header compressed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Deliver {
    /// The sender.
    pub(crate) peer: PeerKey,
    /// The compressed packet.
    pub(crate) payload: Vec<u8>,
    /// Whether the datagram arrived marked Congestion Experienced.
    pub(crate) ce: bool,
}

/// A key the adapter's DNS responder handed to the host, for the node to
/// register before the host's first packet to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Learned {
    /// The peer the name resolved to.
    pub(crate) peer: PeerKey,
    /// This report's number, counting from 1, so that a later
    /// [`FromMesh::ForgotKey`] can say which reports it has seen.
    pub(crate) seq: u64,
}

/// A datagram, or datagrams held for one destination, that the node will
/// not send, handed back so the adapter can answer the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Larger than the node carries to `peer`.
    TooBig {
        /// The destination.
        peer: PeerKey,
        /// The largest payload, in bytes, the node carries to it.
        payload_limit: u16,
        /// The refused payload.
        payload: Vec<u8>,
    },
    /// A session to `peer` would exceed the session table.
    TableFull {
        /// The destination.
        peer: PeerKey,
        /// The refused payload.
        payload: Vec<u8>,
    },
    /// Nothing is working to reach `peer`.
    NoRoute {
        /// The destination.
        peer: PeerKey,
        /// The refused payloads, in the order the host sent them.
        payloads: Vec<Vec<u8>>,
    },
}

/// The node's receiver of the adapter's datagrams.
pub(crate) type DatagramRx = Receiver<Datagram>;
/// The node's receiver of the keys the adapter learned.
pub(crate) type LearnedRx = Receiver<Learned>;

/// The adapter's end of the link: the receiver of everything the node
/// sends, and the senders of what the adapter sends it.
pub(crate) struct MeshLink {
    /// Messages from the node, in order.
    pub(crate) from_mesh: UnboundedReceiver<FromMesh>,
    /// The adapter's datagrams, to the node.
    pub(crate) datagrams: Sender<Datagram>,
    /// The keys the adapter learned, to the node.
    pub(crate) learned: Sender<Learned>,
}

/// The node's end of the link: the sender of everything the adapter receives.
///
/// Dropping every clone ends the link; the adapter then sees its receiver
/// close.
#[derive(Clone)]
pub(crate) struct HostLink {
    /// Messages to the adapter.
    pub(crate) to_host: UnboundedSender<FromMesh>,
}

impl HostLink {
    /// Queue `message` for the adapter. A closed link drops it: the adapter
    /// has gone, and nothing waits on what it would have done.
    pub(crate) fn send(&self, message: FromMesh) {
        let _ = self.to_host.send(message);
    }
}

/// A connected pair of link ends, with the node's two receivers. Only the
/// node's attach step calls this, so holding a [`MeshLink`] is what an
/// attach was granted. `datagrams` and `learned` bound the two channels up.
pub(crate) fn pair(
    datagrams: usize,
    learned: usize,
) -> (MeshLink, HostLink, DatagramRx, LearnedRx) {
    let (to_host, from_mesh) = unbounded_channel();
    let (datagram_tx, datagram_rx) = channel(datagrams);
    let (learned_tx, learned_rx) = channel(learned);
    (
        MeshLink {
            from_mesh,
            datagrams: datagram_tx,
            learned: learned_tx,
        },
        HostLink { to_host },
        datagram_rx,
        learned_rx,
    )
}

#[cfg(test)]
#[path = "tests/link.rs"]
mod tests;
