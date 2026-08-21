//! What a native API client task asks the node to do.
//!
//! The registry lives inside `Node`, so a client task cannot touch it directly.
//! It sends one of these instead and waits on the `oneshot` it carried. That is
//! the same shape the control socket uses, and it is why the receive path needs
//! no lock: only the `rx_loop` ever holds the registry.
//!
//! Every variant that can fail carries its reply channel. A dropped reply means
//! the node is shutting down, which the client task reports as such rather than
//! waiting.

use super::registry::{Arrival, Datagram, Delivery, DropCause, FlowKey, Registry, RegistryError};
use crate::identity::NodeAddr;
use secp256k1::XOnlyPublicKey;
use tokio::sync::{mpsc, oneshot};
use tracing::trace;

/// A request from a client task to the node's registry.
#[derive(Debug)]
pub enum NativeMessage {
    /// Bind a listener to a local port, or to an ephemeral one.
    Listen {
        /// The port to hold, or `None` for an ephemeral one.
        port: Option<u16>,
        /// Where the node announces new peers on that port.
        arrivals: mpsc::Sender<Arrival>,
        /// The port actually held, or why none could be.
        reply: oneshot::Sender<Result<u16, RegistryError>>,
    },

    /// Open a flow to a peer.
    Connect {
        /// The far end, by the x-only public key that is its address.
        peer: XOnlyPublicKey,
        /// The far end's port.
        remote: u16,
        /// The local port, or `None` for an ephemeral one.
        local: Option<u16>,
        /// Where the node delivers this flow's datagrams.
        sink: mpsc::Sender<Datagram>,
        /// What the flow holds, or why it could not be opened.
        reply: oneshot::Sender<Result<Opened, RegistryError>>,
    },

    /// Take a flow a listener announced.
    Accept {
        /// Which announced flow.
        flow: u64,
        /// Where the node delivers its datagrams from now on.
        sink: mpsc::Sender<Datagram>,
        /// The flow's key, whatever arrived before it was accepted, and the
        /// payload limit.
        reply: oneshot::Sender<Result<Accepted, RegistryError>>,
    },

    /// Give up a flow whose descriptor closed, or a listener whose port is
    /// being unbound.
    ///
    /// Carries no reply: the sender is a task that is ending and has nothing
    /// left to do with the answer. It is sent from the task rather than from a
    /// `Drop`, so it can be awaited and cannot be silently lost to a full
    /// channel.
    Release {
        /// Flows to forget.
        flows: Vec<FlowKey>,
        /// Listener ports to free, along with anything pending on them.
        listeners: Vec<u16>,
    },

    /// Undo a flow the listener's task promoted but could not hand over.
    ///
    /// Separate from [`NativeMessage::Release`] because the two count
    /// differently: a release is a flow a client finished with, and this is one
    /// no client ever held. Sending one message for both halves of the undo
    /// keeps the registry entry and the counter from disagreeing.
    Discard {
        /// The flow to forget.
        key: FlowKey,
        /// Why it could not be handed over.
        reason: DropReason,
    },

    /// **Debug.** Deliver a datagram as though it had arrived from the mesh.
    ///
    /// This drives the same [`Registry::deliver`](super::registry::Registry::deliver)
    /// the FSP receive path will call, so the dispatch rule is exercised before
    /// the wire exists and the wire, when it lands, changes the caller rather
    /// than the rule.
    Arrive {
        /// The peer it appears to come from, by wire address.
        peer: NodeAddr,
        /// That peer's key, decoded from the npub the caller named. Client
        /// asserted rather than authenticated, which is one of the reasons the
        /// command is gated.
        pubkey: XOnlyPublicKey,
        /// Its source port.
        src: u16,
        /// Its destination port on this node.
        dst: u16,
        /// The payload.
        data: Datagram,
        /// What the registry decided to do with it.
        reply: oneshot::Sender<Outcome>,
    },
}

/// One datagram a client wrote to its descriptor, on its way to the mesh.
///
/// Travels on its own channel rather than through [`NativeMessage`], so a burst
/// of client traffic cannot delay a registration and the data arm can drain in
/// batches the way the TUN arm does.
#[derive(Debug)]
pub struct Outbound {
    /// The flow it belongs to, which carries both ports and the destination.
    pub key: FlowKey,
    /// The destination's address. Always known: a connected flow decoded it
    /// from the npub its client named, and an accepted one took it from the
    /// session that authenticated the peer.
    pub peer: XOnlyPublicKey,
    /// The payload, with no port header: the send path adds that.
    pub payload: Datagram,
}

/// A flow the client opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened {
    /// The local port it holds.
    pub local: u16,
    /// The identifier the client names it by.
    pub flow: u64,
    /// The largest payload it may send, in bytes.
    pub max: u16,
}

/// A flow the client accepted from a listener.
#[derive(Debug)]
pub struct Accepted {
    /// Which flow, in both directions.
    pub key: FlowKey,
    /// The peer's address.
    pub peer: XOnlyPublicKey,
    /// Whatever arrived before the client answered.
    pub held: Vec<Datagram>,
    /// The largest payload it may send, in bytes.
    pub max: u16,
}

/// Why a datagram was not delivered, across every path that can refuse one.
///
/// [`DropCause`] covers the refusals the registry decides. Delivery can also
/// fail after the registry has agreed, when a bounded channel to a client is
/// full, and those three cases are the remaining variants. Keeping one type
/// over the whole set is what lets a counter match be exhaustive: a match over
/// `DropCause` alone would silently miss the case a slow client actually causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// No listener and no flow holds the destination port.
    NoPort,
    /// A listener holds the port but will not hold another pending flow.
    BacklogFull,
    /// The node is at its flow ceiling.
    TooManyFlows,
    /// A flow awaiting accept will hold no more datagrams.
    PendingQueueFull,
    /// An established flow's client is not draining its descriptor.
    FlowQueueFull,
    /// A listener's client is not reading the arrivals it asked for. The flow
    /// is unregistered as well, so nothing is left pending that nobody knows of.
    ArrivalQueueFull,
    /// A listener's client is not reading its descriptor, so the arrival could
    /// not be written to it. Distinct from `ArrivalQueueFull`: that one is the
    /// rx_loop refusing before anything was opened, and this one is a flow the
    /// daemon had already wired and has to take apart again.
    ListenerNotReading,
    /// A listener's client closed its descriptor between the arrival being
    /// taken off the queue and being written to it. The same cleanup as
    /// `ListenerNotReading` and a different counter: this one is a race a
    /// healthy client can lose, and that one is a client falling behind.
    ListenerGone,
}

impl From<DropCause> for DropReason {
    fn from(cause: DropCause) -> Self {
        match cause {
            DropCause::NoPort => DropReason::NoPort,
            DropCause::BacklogFull => DropReason::BacklogFull,
            DropCause::TooManyFlows => DropReason::TooManyFlows,
            DropCause::QueueFull => DropReason::PendingQueueFull,
        }
    }
}

impl DropReason {
    /// The client-facing text for this reason.
    ///
    /// `PendingQueueFull` and `FlowQueueFull` deliberately render alike. They
    /// are distinct to a counter and indistinguishable to a client, which is
    /// what keeps the strings the debug `arrive` command already answers with
    /// unchanged.
    pub fn as_str(self) -> &'static str {
        match self {
            DropReason::NoPort => "no listener or flow on that port",
            DropReason::BacklogFull => "listener backlog full",
            DropReason::TooManyFlows => "node flow ceiling reached",
            DropReason::PendingQueueFull | DropReason::FlowQueueFull => "queue full",
            DropReason::ArrivalQueueFull => "arrival queue full",
            DropReason::ListenerNotReading => "listener not reading arrivals",
            DropReason::ListenerGone => "listener closed",
        }
    }
}

/// What became of a delivered datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// An established flow received it.
    Delivered,
    /// A listener was told a new peer arrived, and the datagram was held for
    /// whoever accepts it.
    Announced(u64),
    /// A flow already announced held it while it waits to be accepted.
    Held(u64),
    /// Nothing took it.
    Dropped(DropReason),
}

/// What one served request did, so the shell can count it.
///
/// The core decides and answers the client on the request's own channel; this
/// exists only so the node can bump a counter without the core having to know
/// what a counter is. Only outcomes something counts are named; everything else
/// is [`Served::Untracked`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// A client opened a flow to a peer it named.
    Opened,
    /// A listener's task took a pending flow on a client's behalf.
    Accepted,
    /// A flow the daemon wired and could not hand over was taken apart again.
    Discarded(DropReason),
    /// This many established flows were given back when their descriptors
    /// closed or their listener unbound.
    Released(usize),
    /// A datagram of this many bytes was dispatched by the debug arrival
    /// command, which runs the same rule the wire does and is counted the same
    /// way. The length rides along because `deliver` consumes the datagram.
    Delivered(Outcome, usize),
    /// Nothing counted: a listen, or a request the registry refused.
    Untracked,
}

/// Apply one request to `registry` and answer it.
///
/// A free function over the registry rather than a method on the node: the node
/// supplies only `now`, and everything else here is a decision plus the sends
/// that decision names. That is what lets this be driven in a test without
/// building a node, and it is the same code the running daemon executes.
pub fn serve(registry: &mut Registry, message: NativeMessage, now: u64, max: u16) -> Served {
    match message {
        NativeMessage::Listen {
            port,
            arrivals,
            reply,
        } => {
            let _ = reply.send(registry.listen(port, arrivals));
            Served::Untracked
        }

        NativeMessage::Discard { key, reason } => {
            registry.release(&key);
            Served::Discarded(reason)
        }

        NativeMessage::Connect {
            peer,
            remote,
            local,
            sink,
            reply,
        } => {
            let opened = registry
                .connect(peer, remote, local, sink, now)
                .map(|(local, flow)| Opened { local, flow, max });
            let served = if opened.is_ok() {
                Served::Opened
            } else {
                Served::Untracked
            };
            let _ = reply.send(opened);
            served
        }

        NativeMessage::Accept { flow, sink, reply } => {
            let accepted = registry
                .accept(flow, sink, now)
                .map(|(key, peer, held)| Accepted {
                    key,
                    peer,
                    held,
                    max,
                });
            let served = if accepted.is_ok() {
                Served::Accepted
            } else {
                Served::Untracked
            };
            let _ = reply.send(accepted);
            served
        }

        NativeMessage::Release { flows, listeners } => {
            let mut closed = 0;
            for key in &flows {
                if registry.release(key) {
                    closed += 1;
                }
            }
            for port in &listeners {
                registry.release_listener(*port);
            }
            Served::Released(closed)
        }

        NativeMessage::Arrive {
            peer,
            pubkey,
            src,
            dst,
            data,
            reply,
        } => {
            let bytes = data.len();
            let outcome = deliver(registry, peer, pubkey, src, dst, data, now);
            let _ = reply.send(outcome);
            Served::Delivered(outcome, bytes)
        }
    }
}

/// Deliver one inbound datagram to whatever owns its destination port.
///
/// The FSP receive path calls this once the wire is connected; until then the
/// debug arrival command is its only caller. Either way the decision is the
/// registry's and this only performs it.
pub fn deliver(
    registry: &mut Registry,
    peer: NodeAddr,
    pubkey: XOnlyPublicKey,
    src: u16,
    dst: u16,
    data: Datagram,
    now: u64,
) -> Outcome {
    match registry.deliver(peer, pubkey, src, dst, now) {
        Delivery::Flow(sink) => {
            // Never block the receive path on a slow client. A full queue costs
            // that client a datagram, not the node its tick.
            match sink.try_send(data) {
                Ok(()) => Outcome::Delivered,
                Err(_) => {
                    trace!(dst, "Native API flow queue full, dropping datagram");
                    Outcome::Dropped(DropReason::FlowQueueFull)
                }
            }
        }

        Delivery::Arrived(arrivals, arrival) => {
            let flow = arrival.flow;
            if arrivals.try_send(arrival).is_err() {
                // The client is not reading its own announcements. Undo the
                // registration rather than leaving a pending flow nobody will
                // ever be told about.
                let _ = registry.reject(flow);
                return Outcome::Dropped(DropReason::ArrivalQueueFull);
            }
            if registry.hold(flow, data) {
                Outcome::Announced(flow)
            } else {
                Outcome::Dropped(DropReason::PendingQueueFull)
            }
        }

        Delivery::Pending(flow) => {
            if registry.hold(flow, data) {
                Outcome::Held(flow)
            } else {
                Outcome::Dropped(DropReason::PendingQueueFull)
            }
        }

        Delivery::Drop(cause) => Outcome::Dropped(cause.into()),
    }
}
