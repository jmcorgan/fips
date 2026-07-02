//! Platform-pushed peer discovery.
//!
//! A generic seam for an embedding platform (e.g. an Android app layer that
//! runs its own radio discovery, such as Wi-Fi Aware) to push "peer `npub` is
//! reachable at `addr` over transport type `T`" events into a running node —
//! the transport-agnostic generalization of the LAN mDNS drain
//! (`poll_lan_discovery`), which delivers the same shape but is hardwired to
//! UDP transports.
//!
//! The queue is a process-global, like the Android BLE bridge injection seam
//! (`set_android_ble_bridge`): the embedder pushes without holding a `Node`
//! handle, and the node drains once per tick in `poll_platform_discovery`.
//! Events pushed while no node is running are retained up to [`QUEUE_CAP`]
//! (oldest dropped first) so a push racing a node rebuild is not lost.
//! With more than one node in a process, whichever drains first consumes
//! the events (same caveat as the BLE bridge) — intended for the
//! single-node embedding case.
//!
//! The pushed npub is only a routing hint: the Noise IK handshake is the
//! authentication, exactly as with mDNS adverts — a spoofed push fails the
//! IK exchange and is dropped.

use std::collections::VecDeque;
use std::sync::Mutex;

/// Maximum retained events while undrained. Beyond this the oldest event is
/// dropped: platform pushes are periodic (radio discovery re-fires), so a
/// dropped event is re-learned, while an unbounded queue would grow forever
/// if the node is stopped.
const QUEUE_CAP: usize = 256;

/// A peer reachability event pushed by the embedding platform.
///
/// Addresses and identities are strings at this seam (it is crossed from
/// JNI); they are parsed and validated at drain time, where a bad value is
/// logged and skipped rather than surfaced to the pusher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlatformPeerEvent {
    /// The platform established reachability: dial `addr` on an operational
    /// transport whose type name matches `transport_type`. For `udp` the
    /// selection is family-aware — an IPv6 target picks an IPv6-capable
    /// socket, never a wildcard IPv4 one. For IPv6 link-local addresses the
    /// scope must be a numeric ifindex (`"[fe80::x%3]:4870"`) —
    /// interface-name scopes do not parse.
    Available {
        npub: String,
        addr: String,
        transport_type: String,
    },
    /// The platform observed the link go away (e.g. the Wi-Fi Aware data
    /// path was lost). The node closes any pooled connection it holds for
    /// the peer's current address on that transport so a dead socket is
    /// not re-used; reconnection is left to the ordinary machinery.
    Lost {
        npub: String,
        transport_type: String,
    },
}

static QUEUE: Mutex<VecDeque<PlatformPeerEvent>> = Mutex::new(VecDeque::new());

fn push(event: PlatformPeerEvent) {
    let mut queue = QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    if queue.len() >= QUEUE_CAP {
        queue.pop_front();
    }
    queue.push_back(event);
}

/// Push "peer is reachable at `addr` over `transport_type`".
pub fn platform_peer_available(npub: &str, addr: &str, transport_type: &str) {
    push(PlatformPeerEvent::Available {
        npub: npub.to_string(),
        addr: addr.to_string(),
        transport_type: transport_type.to_string(),
    });
}

/// Push "the platform-managed link to peer went away".
pub fn platform_peer_lost(npub: &str, transport_type: &str) {
    push(PlatformPeerEvent::Lost {
        npub: npub.to_string(),
        transport_type: transport_type.to_string(),
    });
}

/// Drain all queued events. Called by the node once per tick.
pub fn drain_platform_peer_events() -> Vec<PlatformPeerEvent> {
    let mut queue = QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    queue.drain(..).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The queue is a process-global, so tests touching it must not
    /// interleave across test threads.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn push_drain_roundtrip() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        drain_platform_peer_events();
        platform_peer_available("npub1abc", "[fe80::1%3]:4870", "tcp");
        platform_peer_lost("npub1abc", "tcp");
        let events = drain_platform_peer_events();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0],
            PlatformPeerEvent::Available {
                npub: "npub1abc".into(),
                addr: "[fe80::1%3]:4870".into(),
                transport_type: "tcp".into(),
            }
        );
        assert_eq!(
            events[1],
            PlatformPeerEvent::Lost {
                npub: "npub1abc".into(),
                transport_type: "tcp".into(),
            }
        );
        assert!(drain_platform_peer_events().is_empty());
    }

    #[test]
    fn queue_caps_by_dropping_oldest() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        drain_platform_peer_events();
        for i in 0..(QUEUE_CAP + 10) {
            platform_peer_available(&format!("npub{i}"), "addr", "tcp");
        }
        let events = drain_platform_peer_events();
        assert_eq!(events.len(), QUEUE_CAP);
        match &events[0] {
            PlatformPeerEvent::Available { npub, .. } => assert_eq!(npub, "npub10"),
            other => panic!("unexpected event: {other:?}"),
        }
    }
}
