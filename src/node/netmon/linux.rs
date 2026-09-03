//! Linux's event-driven medium-change backend: a netlink multicast socket.
//!
//! This is what `ip monitor` listens on. The kernel publishes a message the
//! moment a link changes state, an address is added or removed, or a route
//! appears or goes away — so a Wi-Fi to 5G handover reaches the node in
//! milliseconds instead of on the next poll.
//!
//! # It deliberately does not interpret anything
//!
//! Every message is treated identically: a ping saying "take another sample".
//! The decision about whether anything that matters actually moved stays with
//! [`NetFingerprint`](super::NetFingerprint), shared with every other backend.
//!
//! (`rtnetlink` still *decodes* each message into a `RouteNetlinkMessage` on
//! the way through — that is the library's own parsing of kernel-supplied
//! bytes, on the same footing as every other `rtnetlink` call in the tree. What
//! this backend adds is no inspection of the result.)
//!
//! That is not laziness, it is the property that makes the backend safe. A
//! netlink stream is noisy — route metric churn, neighbour updates, an address
//! flapping and returning — and a backend that classified messages would own a
//! second, subtly different definition of "the medium changed" that could
//! disagree with the fingerprint's. Since the fingerprint has the final say, an
//! over-eager ping costs one comparison and a spurious one costs nothing at all,
//! so the backend is free to be maximally permissive about what it forwards.
//!
//! # Android
//!
//! `target_os = "android"` deliberately does not build this. Android's SELinux
//! policy blocks `NETLINK_ROUTE` multicast for ordinary apps, and Doze suspends
//! the process across exactly the handovers worth catching; the signal there is
//! `ConnectivityManager.registerDefaultNetworkCallback`, pushed in by the
//! embedder over the same channel this backend feeds — the same seam the BLE
//! radio backend uses. Until that lands, Android runs the portable poller.

use std::io;

use futures::StreamExt;
use rtnetlink::MulticastGroup;
use tokio::sync::mpsc;
use tracing::{debug, trace};

/// The multicast groups a medium change shows up in.
///
/// Both address families, and both the interface and route views of each,
/// because the shapes we care about do not all touch the same one: a cable
/// plugged in beside live Wi-Fi is an address event with no default-route
/// change, while a Wi-Fi to 5G handover on a phone that keeps both interfaces
/// up is a route event with no address change. `Link` catches a radio going
/// down before any address has been withdrawn.
const GROUPS: &[MulticastGroup] = &[
    MulticastGroup::Link,
    MulticastGroup::Ipv4Ifaddr,
    MulticastGroup::Ipv6Ifaddr,
    MulticastGroup::Ipv4Route,
    MulticastGroup::Ipv6Route,
];

/// Start the netlink backend, returning the channel it pings.
///
/// Binding the socket happens here, synchronously, so a kernel or sandbox that
/// refuses the subscription is reported to the caller as a startup failure it
/// can fall back from — rather than surfacing later as a detector that silently
/// never fires.
pub(super) fn spawn_netlink_backend() -> io::Result<mpsc::Receiver<()>> {
    let (connection, _handle, mut messages) = rtnetlink::new_multicast_connection(GROUPS)?;

    // Single slot: the wake source only needs to know that *something* arrived,
    // so a burst of messages during a handover must collapse into one wake-up
    // rather than queueing one per message and re-sampling dozens of times.
    let (tx, rx) = mpsc::channel(1);

    // The connection drives the socket; it must be on the runtime for messages
    // to arrive at all.
    tokio::spawn(connection);

    tokio::spawn(async move {
        debug!("Netlink medium-change backend listening");
        while let Some((message, _addr)) = messages.next().await {
            trace!(?message, "Netlink notification");
            match tx.try_send(()) {
                // Already pinged and not yet consumed — this message is part of
                // the same burst and needs no second wake-up.
                Ok(()) | Err(mpsc::error::TrySendError::Full(())) => {}
                Err(mpsc::error::TrySendError::Closed(())) => {
                    debug!("Netlink backend receiver gone; stopping");
                    return;
                }
            }
        }
        // The connection ended: the socket errored, or the node is shutting
        // down. Dropping `tx` closes the channel, which the wake source reads
        // as "this backend is gone" and falls back to polling.
        debug!("Netlink message stream ended");
    });

    Ok(rx)
}
