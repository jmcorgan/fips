//! Serve the native API registry from inside the `rx_loop`.
//!
//! The registry lives in `Node`, so every client request arrives here and is
//! answered on the `oneshot` it carried. Nothing else touches the registry,
//! which is why the receive path takes no lock.
//!
//! The work itself is in [`crate::native::link`], as a free function over the
//! registry. This file supplies the clock and nothing else, so the logic the
//! daemon runs is the same logic a test drives without building a node.

use crate::identity::NodeAddr;
use crate::native::link::{self, NativeMessage, Outcome, Served};
use crate::native::registry::FlowKey;
use crate::node::Node;
use crate::proto::fsp::wire::FSP_PORT_HEADER_SIZE;
use crate::upper::icmp::FIPS_OVERHEAD;
use secp256k1::XOnlyPublicKey;
use tracing::debug;

/// One native datagram held while its destination's session establishes.
///
/// Carries its ports, which is exactly what the TUN pending queue lacks and
/// why native datagrams need a queue of their own.
#[derive(Debug, Clone)]
pub(in crate::node) struct PendingNative {
    /// The flow this datagram belongs to.
    pub key: FlowKey,
    /// The payload, without any port header: `send_session_data` adds that.
    pub payload: Vec<u8>,
}

impl Node {
    /// Answer one native API request, and count what it did.
    ///
    /// The counting is here rather than in [`link::serve`] because the core
    /// decides and the shell observes. `serve` reports its outcome and knows
    /// nothing about counters.
    pub(in crate::node) fn handle_native(&mut self, message: NativeMessage) {
        let max = self.native_max_payload();
        let served = link::serve(&mut self.native, message, Self::now_ms(), max);
        let native = &self.metrics.native;
        match served {
            Served::Opened => native.flows_opened.inc(),
            Served::Accepted => native.flows_accepted.inc(),
            Served::Discarded(reason) => native.record_drop(reason),
            Served::Released(closed) => native.flows_closed.add(closed as u64),
            Served::Delivered(outcome, bytes) => self.count_native_delivery(outcome, bytes),
            Served::Untracked => {}
        }
    }

    /// Count one dispatched inbound datagram.
    ///
    /// Shared by the wire path and the debug arrival command, which run the same
    /// dispatch, so a counter cannot disagree between them.
    fn count_native_delivery(&self, outcome: Outcome, bytes: usize) {
        let native = &self.metrics.native;
        match outcome {
            Outcome::Delivered | Outcome::Announced(_) | Outcome::Held(_) => {
                native.record_received(bytes);
            }
            Outcome::Dropped(reason) => native.record_drop(reason),
        }
    }

    /// Deliver one inbound datagram to whatever owns its destination port.
    ///
    /// `pubkey` is the peer's address, read from the session entry that
    /// authenticated it. It is captured here, at the one call site the wire
    /// has, rather than resolved when a report is rendered: the node address
    /// the wire carries is a truncated hash and does not invert.
    pub(in crate::node) fn native_deliver(
        &mut self,
        peer: crate::identity::NodeAddr,
        pubkey: XOnlyPublicKey,
        src: u16,
        dst: u16,
        data: Vec<u8>,
    ) -> Outcome {
        let bytes = data.len();
        let outcome = link::deliver(
            &mut self.native,
            peer,
            pubkey,
            src,
            dst,
            data,
            Self::now_ms(),
        );
        self.count_native_delivery(outcome, bytes);
        outcome
    }

    /// The largest payload a native flow may send, in bytes.
    ///
    /// Wire size is `FIPS_OVERHEAD` plus the four-byte port header plus the
    /// payload, so the payload is whatever is left of the transport MTU. This
    /// is 40 bytes more than the same application data gets through the IPv6
    /// shim, which spends them on a header the application never sees.
    pub(in crate::node) fn native_max_payload(&self) -> u16 {
        self.transport_mtu()
            .saturating_sub(FIPS_OVERHEAD)
            .saturating_sub(FSP_PORT_HEADER_SIZE as u16)
    }

    /// Send one datagram a native API client wrote to its descriptor.
    ///
    /// Mirrors `handle_tun_outbound` with three differences: the destination
    /// comes from the flow rather than from a parsed IPv6 header, an error is
    /// reported to the client rather than as an ICMPv6 message, and the flow's
    /// own ports are used instead of the shim's.
    pub(in crate::node) async fn handle_native_outbound(
        &mut self,
        key: FlowKey,
        peer: XOnlyPublicKey,
        payload: Vec<u8>,
    ) {
        let max = self.native_max_payload() as usize;
        if payload.len() > max {
            debug!(
                len = payload.len(),
                max, "Native API datagram exceeds the path payload limit, dropping"
            );
            self.metrics.native.drop_oversize.inc();
            return;
        }

        if let Some(entry) = self.sessions.get(&key.peer) {
            if entry.is_established() {
                let bytes = payload.len();
                if let Err(error) = self
                    .send_session_data(&key.peer, key.local, key.remote, &payload)
                    .await
                {
                    debug!(
                        peer = %self.peer_display_name(&key.peer),
                        error = %error,
                        "Failed to send a native datagram"
                    );
                    self.relookup_lost_route(&key.peer).await;
                } else {
                    self.metrics.native.record_sent(bytes);
                }
                return;
            }
            self.queue_native(key, payload);
            return;
        }

        // No session. Start one and hold the datagram; if there is no route,
        // ask discovery for one and hold it anyway, exactly as the TUN path
        // does.
        //
        // Every flow carries its peer's address, whether the client named it or
        // the session authenticated it, so there is no cache lookup here and no
        // datagram dropped for want of a key. `initiate_session` wants a full
        // key, and the parity it is lifted with does not matter: the handshake
        // hashes the DH output x-only and forces even parity in the XK
        // premessage, so both parities derive the same material.
        let pubkey = peer.public_key(secp256k1::Parity::Even);

        // Cache the key the client supplied before trying the route. If there
        // is none, the lookup below verifies its answer against this cache, and
        // `initiate_session` registers the key only after a send succeeds, so
        // without this the answer is dropped. Only on a miss, the same rule
        // `cache_session_identity` follows: when no route is known, a key
        // already cached from DNS, a handshake or a configured peer keeps its
        // own parity. The presence check refreshes that entry, so it is not
        // the oldest one when the answer arrives.
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&key.peer.as_bytes()[0..15]);
        if self.lookup_by_fips_prefix(&prefix).is_none() {
            self.register_identity(key.peer, pubkey);
        }

        if let Err(error) = self.initiate_session(key.peer, pubkey).await {
            debug!(
                peer = %self.peer_display_name(&key.peer),
                error = %error,
                "Failed to initiate a session for a native flow, trying discovery"
            );
            self.maybe_initiate_lookup(&key.peer).await;
        }
        self.queue_native(key, payload);
    }

    /// Hold a native datagram until its destination's session establishes.
    ///
    /// Bounded the same way the TUN queue is, and by the same configured
    /// numbers, so one client cannot make the node hold without limit.
    fn queue_native(&mut self, key: FlowKey, payload: Vec<u8>) {
        let max_dests = self.config().node.session.pending_max_destinations;
        if !self.pending_native.contains_key(&key.peer) && self.pending_native.len() >= max_dests {
            return;
        }
        let per_dest = self.config().node.session.pending_packets_per_dest;
        let queue = self.pending_native.entry(key.peer).or_default();
        crate::proto::fsp::push_bounded_pending(queue, PendingNative { key, payload }, per_dest);
    }

    /// Send the native datagrams held for a destination whose session is up.
    ///
    /// Called beside `flush_pending_packets` at every site that flushes the TUN
    /// queue. A separate queue means a separate flush, and forgetting one would
    /// leave datagrams held until the session went away.
    pub(in crate::node) async fn flush_pending_native(&mut self, dest: &NodeAddr) {
        let Some(held) = self.pending_native.remove(dest) else {
            return;
        };
        for entry in held {
            let bytes = entry.payload.len();
            if let Err(error) = self
                .send_session_data(dest, entry.key.local, entry.key.remote, &entry.payload)
                .await
            {
                debug!(
                    peer = %self.peer_display_name(dest),
                    error = %error,
                    "Failed to send a queued native datagram"
                );
                break;
            }
            self.metrics.native.record_sent(bytes);
        }
    }

    /// The native API's maintenance tick work.
    ///
    /// Two jobs. First, discard pending flows a listener's task never wired.
    /// The window that closes is the hop between the rx_loop announcing an
    /// arrival and the listener's task taking it, so a non-zero count is the
    /// daemon failing to complete an arrival rather than a client failing to
    /// answer for one. It should be zero on a healthy node.
    ///
    /// Second, release held datagrams for destinations with no session and
    /// no lookup (see [`Self::purge_native`]). The purge is called from here
    /// rather than beside this call in the tick so that tests driving this
    /// function also cover the tick's wiring, which no unit test can reach
    /// inside the rx_loop.
    pub(in crate::node) fn native_expire(&mut self) {
        let expired = self.native.expire(Self::now_ms());
        self.metrics.native.flows_expired.add(expired.len() as u64);
        if !expired.is_empty() {
            debug!(
                count = expired.len(),
                "Native API pending flows expired without an answer"
            );
        }
        self.purge_native();
    }

    /// Release native datagrams held for a destination nothing of ours is
    /// still trying to reach.
    ///
    /// A held datagram leaves only when its destination's session
    /// establishes. Once the destination has neither a session entry, in any
    /// state, nor a pending lookup, nothing of ours is still working to
    /// establish one, so the datagram could be held for the daemon's life and
    /// would count against `pending_max_destinations` until every new
    /// destination was refused. The cost is that a session which comes up
    /// later for another reason, such as the peer initiating or a later send
    /// of ours, no longer finds the datagram. One predicate rather than a hook
    /// per event, because some ways of reaching that state fire no event: a
    /// lookup gated by a bloom miss or by backoff never creates a session
    /// entry or a pending lookup.
    fn purge_native(&mut self) {
        let sessions = &self.sessions;
        let lookups = &self.lookup.pending_lookups;
        let before = self.pending_native.len();
        let mut datagrams = 0usize;
        self.pending_native.retain(|dest, held| {
            let live = sessions.contains_key(dest) || lookups.contains_key(dest);
            if !live {
                datagrams += held.len();
            }
            live
        });
        let destinations = before - self.pending_native.len();
        if destinations > 0 {
            debug!(
                destinations,
                datagrams,
                "Released native datagrams held for destinations with no session or lookup"
            );
        }
    }
}
