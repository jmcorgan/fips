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

use secp256k1::XOnlyPublicKey;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::{Ipv6Address, NodeAddr};

/// The FSP port the IPv6 adapter's traffic uses.
pub(crate) const IPV6_PORT: u16 = 256;

/// A peer named by the 32 bytes of its x-only public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PeerKey(XOnlyPublicKey);

impl PeerKey {
    /// The key of the peer whose x-only public key is `key`.
    pub(crate) fn new(key: XOnlyPublicKey) -> Self {
        Self(key)
    }

    /// Some peer's key, for a test that needs one but not a particular one.
    #[cfg(test)]
    pub(crate) fn any() -> Self {
        Self(crate::Identity::generate().pubkey())
    }

    /// The peer's IPv6 address: the `fd00::/8` form of the node address its
    /// key hashes to.
    pub(crate) fn address(&self) -> Ipv6Address {
        Ipv6Address::from_node_addr(&NodeAddr::from_pubkey(&self.0))
    }
}

/// The adapter's request to attach to the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Attach {
    /// The FSP port the adapter serves, `Some(256)` while the TUN is enabled.
    pub(crate) port: Option<u16>,
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
}

/// The adapter's end of the link: the receiver of everything the node sends.
pub(crate) struct MeshLink {
    /// Messages from the node, in order.
    pub(crate) from_mesh: UnboundedReceiver<FromMesh>,
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

/// A connected pair of link ends. Only the node's attach step calls this,
/// so holding a [`MeshLink`] is what an attach was granted.
pub(crate) fn pair() -> (MeshLink, HostLink) {
    let (to_host, from_mesh) = unbounded_channel();
    (MeshLink { from_mesh }, HostLink { to_host })
}

#[cfg(test)]
#[path = "tests/link.rs"]
mod tests;
