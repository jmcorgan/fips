//! Which local ports the native API holds, and where an inbound datagram goes.
//!
//! The registry is the node's, not a client connection's: two clients must
//! conflict with each other over a port, and an inbound datagram has to find its
//! flow without knowing which connection opened it. It lives inside `Node` and
//! is reached from the client tasks through the `rx_loop`, so there is no lock
//! on the receive path.
//!
//! Everything here is a decision over maps. No I/O, no clock read, no sockets:
//! the caller passes the time in and performs whatever the decision names. That
//! is what lets the delivery rule be tested without a wire, and it is why the
//! same [`Registry::deliver`] serves both the debug arrival command and, once it
//! exists, the real FSP receive path.

use crate::identity::NodeAddr;
use secp256k1::XOnlyPublicKey;
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::mpsc::Sender;

use super::protocol::{PORT_EPHEMERAL_MIN, check_bindable};

/// How long a flow stays pending between the announcement and the listener
/// task wiring it, in milliseconds.
///
/// Compiled in rather than configured: the window it bounds is a task hop
/// inside the daemon, not a client's behaviour, so an operator has nothing to
/// tune it against. Five seconds is generous for a hop and short enough that a
/// wedged listener task cannot accumulate pending flows. It is reasoned rather
/// than measured, and the announce-to-wired latency under load is what would
/// settle it.
pub const PENDING_DEADLINE_MS: u64 = 5_000;

/// What identifies one flow on the wire, in both directions.
///
/// The local port alone is not enough: two peers may both send to a listener's
/// port, and each is a separate flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// The far end.
    pub peer: NodeAddr,
    /// The far end's port.
    pub remote: u16,
    /// This node's port.
    pub local: u16,
}

/// A datagram handed to an established flow.
pub type Datagram = Vec<u8>;

/// What a listener is told when a new peer arrives on its port.
#[derive(Debug, Clone)]
pub struct Arrival {
    /// The identifier the listener's task names the flow by.
    pub flow: u64,
    /// Which flow arrived.
    pub key: FlowKey,
    /// The peer's address, as the x-only public key its session authenticated.
    /// Carried here rather than resolved later because the node address in
    /// `key` is a truncated hash and does not invert.
    pub pubkey: XOnlyPublicKey,
}

/// Bounds on what the registry will hold.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Datagrams held for one flow, whether pending accept or established.
    pub per_flow: usize,
    /// Flows awaiting accept on one listener.
    pub backlog: usize,
    /// Flows this node holds at once, across every client.
    pub max_flows: usize,
}

/// Why a registry request was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RegistryError {
    /// Another listener or flow already holds this local port.
    #[error("port {0} is already in use on this node")]
    PortTaken(u16),

    /// A flow to that peer between those two ports already exists.
    ///
    /// Distinct from [`RegistryError::PortTaken`], and reachable when that one
    /// is not: a flow accepted from a listener never owned the listener's port,
    /// so closing the listener leaves the port free while the flow's key is
    /// still held. The key is what an inbound datagram is demultiplexed on, so
    /// a second flow carrying it would take the first one's traffic.
    #[error("a flow to that peer between ports {local} and {remote} already exists")]
    FlowTaken {
        /// This node's port.
        local: u16,
        /// The far end's port.
        remote: u16,
    },

    /// Every port in the ephemeral range is held.
    #[error("no ephemeral port is free")]
    NoPort,

    /// The node is already holding as many flows as it will.
    #[error("this node holds its maximum of {0} flows")]
    TooManyFlows(usize),

    /// The listener already has as many unaccepted flows as it will hold.
    #[error("listener on port {0} has a full backlog")]
    BacklogFull(u16),

    /// No pending flow carries this identifier.
    #[error("no pending flow {0}")]
    NoPending(u64),

    /// The port is one a client may not name.
    #[error("{0}")]
    Port(#[from] super::protocol::CommandError),
}

/// Where an inbound datagram goes.
#[derive(Debug)]
pub enum Delivery<'a> {
    /// An established flow owns it. The caller sends on this.
    Flow(&'a Sender<Datagram>),
    /// A listener owns the port and this peer is new to it. The caller raises
    /// the arrival on that listener, then holds the datagram against the flow.
    Arrived(&'a Sender<Arrival>, Arrival),
    /// This flow was already announced and is waiting to be accepted. The
    /// caller holds the datagram against it with [`Registry::hold`], and counts
    /// a [`DropCause::QueueFull`] if it will not fit.
    Pending(u64),
    /// Nothing owns the port, or a bound is full. Count it and drop it.
    Drop(DropCause),
}

/// Why a datagram was not delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropCause {
    /// No listener and no flow holds the destination port.
    NoPort,
    /// A listener holds the port but will not hold another pending flow.
    BacklogFull,
    /// The node is at its flow ceiling.
    TooManyFlows,
    /// The flow is pending accept and its queue is full.
    QueueFull,
}

/// What holds a local port.
#[derive(Debug)]
enum Owner {
    /// A listener, which may own many flows on this port.
    Listener,
    /// One connected flow.
    Flow(FlowKey),
}

/// A listener bound to a local port.
struct Listener {
    /// Where arrivals are announced.
    arrivals: Sender<Arrival>,
    /// Flows announced on this listener and not yet taken by its task.
    pending: Vec<u64>,
}

/// A flow the client has accepted or opened.
struct Flow {
    /// The peer's address, so every report of this flow names the peer the
    /// same way a connected flow's client named it.
    pubkey: XOnlyPublicKey,
    /// Where its datagrams go.
    sink: Sender<Datagram>,
    /// When the client took it, in milliseconds. A pending flow already
    /// records its announcement time; an established one needs its own, or an
    /// observer cannot tell a flow opened an hour ago from one opened just now.
    at: u64,
}

/// A flow announced to a listener and awaiting the client's answer.
struct Pending {
    key: FlowKey,
    /// The peer's address, captured where the session authenticated it.
    pubkey: XOnlyPublicKey,
    /// The port whose listener announced it.
    listener: u16,
    /// Datagrams held until the client accepts, so the first message from a new
    /// peer is not lost to the accept round trip.
    held: Vec<Datagram>,
    /// When the arrival was announced, in milliseconds.
    at: u64,
}

/// One flow as an observer sees it.
///
/// A copy rather than a borrow of the registry's own entry: the caller projects
/// it into a control snapshot the control socket reads off the rx_loop, and the
/// registry itself never leaves the loop that owns it.
#[derive(Debug, Clone, Copy)]
pub struct FlowView {
    /// The identifier the client names it by.
    pub flow: u64,
    /// The peer and both ports.
    pub key: FlowKey,
    /// The peer's address. Always present, for an accepted flow as much as for
    /// a connected one, because it is captured rather than resolved.
    pub pubkey: XOnlyPublicKey,
    /// Whether a client has taken it, as opposed to still awaiting accept.
    pub established: bool,
    /// Datagrams the node is holding for it: what a pending flow has kept back
    /// for whoever accepts it, or what an established flow's client has not yet
    /// read off its descriptor.
    pub queued: usize,
    /// When it was opened, accepted, or announced, in milliseconds.
    pub at: u64,
}

/// One listener as an observer sees it.
#[derive(Debug, Clone, Copy)]
pub struct ListenerView {
    /// The local port it holds.
    pub port: u16,
    /// Flows announced on it and not yet answered.
    pub backlog: usize,
}

/// The node's native API registry.
pub struct Registry {
    ports: HashMap<u16, Owner>,
    listeners: HashMap<u16, Listener>,
    flows: HashMap<FlowKey, Flow>,
    /// Client-facing identifiers for established flows. A client names a flow
    /// by number rather than by the three-part key, and the numbers come from
    /// the same counter as pending flows so the two can never collide.
    by_id: HashMap<u64, FlowKey>,
    pending: HashMap<u64, Pending>,
    limits: Limits,
    next_flow: u64,
    next_ephemeral: u16,
}

impl Registry {
    /// An empty registry under `limits`.
    pub fn new(limits: Limits) -> Self {
        Self {
            ports: HashMap::new(),
            listeners: HashMap::new(),
            flows: HashMap::new(),
            by_id: HashMap::new(),
            pending: HashMap::new(),
            limits,
            next_flow: 1,
            next_ephemeral: PORT_EPHEMERAL_MIN,
        }
    }

    /// How many flows the node holds, established and pending.
    pub fn flow_count(&self) -> usize {
        self.flows.len() + self.pending.len()
    }

    /// How many local ports are held.
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Every flow the node holds, established and pending, ordered by
    /// identifier so a reader sees a stable list across reads.
    ///
    /// An established flow's queue depth is what its bounded channel is
    /// carrying, which is the same thing a pending flow's held datagrams are:
    /// what the node is keeping because the client has not taken it yet.
    pub fn flows(&self) -> Vec<FlowView> {
        let established = self.by_id.iter().filter_map(|(id, key)| {
            let flow = self.flows.get(key)?;
            Some(FlowView {
                flow: *id,
                key: *key,
                pubkey: flow.pubkey,
                established: true,
                queued: flow
                    .sink
                    .max_capacity()
                    .saturating_sub(flow.sink.capacity()),
                at: flow.at,
            })
        });
        let pending = self.pending.iter().map(|(id, entry)| FlowView {
            flow: *id,
            key: entry.key,
            pubkey: entry.pubkey,
            established: false,
            queued: entry.held.len(),
            at: entry.at,
        });
        let mut views: Vec<FlowView> = established.chain(pending).collect();
        views.sort_by_key(|view| view.flow);
        views
    }

    /// Every listener the node holds, ordered by port.
    pub fn listeners(&self) -> Vec<ListenerView> {
        let mut views: Vec<ListenerView> = self
            .listeners
            .iter()
            .map(|(port, listener)| ListenerView {
                port: *port,
                backlog: listener.pending.len(),
            })
            .collect();
        views.sort_by_key(|view| view.port);
        views
    }

    /// Bind a listener to `port`, or to an ephemeral one when it is `None`,
    /// announcing arrivals on `arrivals`.
    ///
    /// Returns the port actually held, which is what a client that asked for
    /// an ephemeral one needs and is what `getsockname` reports after a
    /// `bind(2)` with port 0. A named port still goes through
    /// [`check_bindable`], so the reserved tiers are refused either way.
    ///
    /// A port that only accepted flows still hold is bindable, and the new
    /// listener hears from new peers alone: an established key outranks the
    /// port in [`Registry::deliver`], so the flows that outlived the previous
    /// listener keep their own traffic.
    pub fn listen(
        &mut self,
        port: Option<u16>,
        arrivals: Sender<Arrival>,
    ) -> Result<u16, RegistryError> {
        let port = match port {
            Some(port) => {
                check_bindable(port)?;
                if self.ports.contains_key(&port) {
                    return Err(RegistryError::PortTaken(port));
                }
                port
            }
            None => self.take_ephemeral()?,
        };
        self.ports.insert(port, Owner::Listener);
        self.listeners.insert(
            port,
            Listener {
                arrivals,
                pending: Vec::new(),
            },
        );
        Ok(port)
    }

    /// Open a flow to `peer` on `remote`, from `local` or an ephemeral port.
    ///
    /// The peer is named by its x-only public key, which is the address, and
    /// the node address the wire keys on is derived from it here rather than
    /// passed alongside: two arguments naming one peer could disagree.
    ///
    /// Returns the local port the flow holds and the identifier the client uses
    /// to name it. `now` is kept so the flow can report its own age.
    pub fn connect(
        &mut self,
        peer: XOnlyPublicKey,
        remote: u16,
        local: Option<u16>,
        sink: Sender<Datagram>,
        now: u64,
    ) -> Result<(u16, u64), RegistryError> {
        check_bindable(remote)?;
        if self.flow_count() >= self.limits.max_flows {
            return Err(RegistryError::TooManyFlows(self.limits.max_flows));
        }

        let local = match local {
            Some(port) => {
                check_bindable(port)?;
                if self.ports.contains_key(&port) {
                    return Err(RegistryError::PortTaken(port));
                }
                port
            }
            None => self.take_ephemeral()?,
        };

        let key = FlowKey {
            peer: NodeAddr::from_pubkey(&peer),
            remote,
            local,
        };
        // Checked before the port is claimed, so a refusal leaves nothing to
        // undo. Inserting over a live entry instead would drop that flow's sink
        // without telling its client, and hand the older flow's release the
        // power to free a port the newer one now owns. Only established flows
        // are consulted: a pending flow sits on a live listener's port, and
        // that listener refuses this call above.
        if self.flows.contains_key(&key) {
            return Err(RegistryError::FlowTaken { local, remote });
        }
        let id = self.next_flow;
        self.next_flow += 1;
        self.ports.insert(local, Owner::Flow(key));
        self.flows.insert(
            key,
            Flow {
                pubkey: peer,
                sink,
                at: now,
            },
        );
        self.by_id.insert(id, key);
        Ok((local, id))
    }

    /// The key of an established flow, by the identifier a client holds.
    pub fn key_of(&self, flow: u64) -> Option<FlowKey> {
        self.by_id.get(&flow).copied()
    }

    /// Claim a free port from the ephemeral range.
    ///
    /// Sweeps forward from where the last claim left off and wraps once, so a
    /// port is not reused immediately after it is released.
    fn take_ephemeral(&mut self) -> Result<u16, RegistryError> {
        let span = u32::from(u16::MAX - PORT_EPHEMERAL_MIN) + 1;
        for _ in 0..span {
            let port = self.next_ephemeral;
            self.next_ephemeral = if port == u16::MAX {
                PORT_EPHEMERAL_MIN
            } else {
                port + 1
            };
            if !self.ports.contains_key(&port) {
                return Ok(port);
            }
        }
        Err(RegistryError::NoPort)
    }

    /// Decide where an inbound datagram goes.
    ///
    /// Three steps, in order: an established flow that matches the whole key, a
    /// listener on the destination port, then nothing. The order is what makes a
    /// reply from a known peer reach its own flow rather than announcing itself
    /// as a new arrival every time, and it is what keeps a flow that outlived
    /// its listener receiving after another client has rebound the port.
    ///
    /// `peer` is what the wire supplied and is what every lookup keys on.
    /// `pubkey` is what the session authenticated, and is used by the announce
    /// arm alone: it is the address a new flow carries for the rest of its life.
    pub fn deliver(
        &mut self,
        peer: NodeAddr,
        pubkey: XOnlyPublicKey,
        src: u16,
        dst: u16,
        now: u64,
    ) -> Delivery<'_> {
        let key = FlowKey {
            peer,
            remote: src,
            local: dst,
        };

        // A flow already announced and not yet answered holds its datagrams
        // rather than announcing again, so a peer that keeps sending does not
        // fill the backlog with duplicates of itself.
        if let Some(id) = self.pending_for(&key) {
            return Delivery::Pending(id);
        }

        if self.flows.contains_key(&key) {
            let sink = &self.flows.get(&key).expect("checked above").sink;
            return Delivery::Flow(sink);
        }

        if !self.listeners.contains_key(&dst) {
            return Delivery::Drop(DropCause::NoPort);
        }
        if self.flow_count() >= self.limits.max_flows {
            return Delivery::Drop(DropCause::TooManyFlows);
        }
        {
            let listener = self.listeners.get(&dst).expect("checked above");
            if listener.pending.len() >= self.limits.backlog {
                return Delivery::Drop(DropCause::BacklogFull);
            }
        }

        let id = self.next_flow;
        self.next_flow += 1;
        self.pending.insert(
            id,
            Pending {
                key,
                pubkey,
                listener: dst,
                held: Vec::new(),
                at: now,
            },
        );
        let listener = self.listeners.get_mut(&dst).expect("checked above");
        listener.pending.push(id);
        let arrival = Arrival {
            flow: id,
            key,
            pubkey,
        };
        Delivery::Arrived(&listener.arrivals, arrival)
    }

    /// Hold a datagram for a pending flow, reporting whether it fitted.
    pub fn hold(&mut self, flow: u64, datagram: Datagram) -> bool {
        let Some(entry) = self.pending.get_mut(&flow) else {
            return false;
        };
        if entry.held.len() >= self.limits.per_flow {
            return false;
        }
        entry.held.push(datagram);
        true
    }

    /// The pending flow carrying `key`, if one was announced.
    fn pending_for(&self, key: &FlowKey) -> Option<u64> {
        self.pending
            .iter()
            .find(|(_, entry)| entry.key == *key)
            .map(|(id, _)| *id)
    }

    /// Accept a pending flow, returning its key, its peer and whatever it held.
    ///
    /// The held datagrams go back to the caller so the first message from a new
    /// peer reaches the client, rather than being lost to the hop between the
    /// announcement and the listener task wiring the flow.
    pub fn accept(
        &mut self,
        flow: u64,
        sink: Sender<Datagram>,
        now: u64,
    ) -> Result<(FlowKey, XOnlyPublicKey, Vec<Datagram>), RegistryError> {
        let entry = self
            .pending
            .remove(&flow)
            .ok_or(RegistryError::NoPending(flow))?;
        if let Some(listener) = self.listeners.get_mut(&entry.listener) {
            listener.pending.retain(|id| *id != flow);
        }
        self.flows.insert(
            entry.key,
            Flow {
                pubkey: entry.pubkey,
                sink,
                at: now,
            },
        );
        self.by_id.insert(flow, entry.key);
        Ok((entry.key, entry.pubkey, entry.held))
    }

    /// Discard a pending flow and anything it held.
    ///
    /// The undo for an announcement the listener's arrival channel refused:
    /// the entry is registered by then, so dropping the datagram alone would
    /// leave a pending flow nobody will ever be told about.
    pub fn reject(&mut self, flow: u64) -> Result<FlowKey, RegistryError> {
        let entry = self
            .pending
            .remove(&flow)
            .ok_or(RegistryError::NoPending(flow))?;
        if let Some(listener) = self.listeners.get_mut(&entry.listener) {
            listener.pending.retain(|id| *id != flow);
        }
        Ok(entry.key)
    }

    /// Release an established flow and the port it held, if it held one.
    ///
    /// A flow accepted from a listener shares that listener's port and does not
    /// own it, so only a flow the registry recorded as the port's owner
    /// releases it.
    /// Returns whether a flow was actually removed, so a caller counting
    /// closures counts real ones rather than requests to close.
    pub fn release(&mut self, key: &FlowKey) -> bool {
        let removed = self.flows.remove(key).is_some();
        self.by_id.retain(|_, held| held != key);
        if let Some(Owner::Flow(owned)) = self.ports.get(&key.local)
            && owned == key
        {
            self.ports.remove(&key.local);
        }
        removed
    }

    /// Release a listener, its port, and every flow still pending on it.
    ///
    /// **Flows already accepted on that port survive**, which is what
    /// `close(listen_fd)` means: an accepted flow is keyed on its whole
    /// [`FlowKey`] and never owned the listener's port, so it keeps receiving
    /// its own peer's datagrams while the port becomes bindable again. What
    /// stops that from crossing two clients' traffic is [`Registry::deliver`]
    /// matching the key before it looks at the port, and [`Registry::connect`]
    /// refusing a key a live flow already holds.
    pub fn release_listener(&mut self, port: u16) {
        if matches!(self.ports.get(&port), Some(Owner::Listener)) {
            self.ports.remove(&port);
        }
        if let Some(listener) = self.listeners.remove(&port) {
            for flow in listener.pending {
                self.pending.remove(&flow);
            }
        }
    }

    /// Discard pending flows the listener's task never wired.
    ///
    /// Returns what was discarded, so the caller can count it. The window this
    /// closes is a task hop rather than a client round trip, so a non-zero
    /// count means the daemon could not complete an arrival and is worth
    /// alerting on.
    pub fn expire(&mut self, now: u64) -> Vec<u64> {
        let deadline = PENDING_DEADLINE_MS;
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, entry)| now.saturating_sub(entry.at) >= deadline)
            .map(|(id, _)| *id)
            .collect();
        for flow in &expired {
            if let Some(entry) = self.pending.remove(flow)
                && let Some(listener) = self.listeners.get_mut(&entry.listener)
            {
                listener.pending.retain(|id| id != flow);
            }
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn limits() -> Limits {
        Limits {
            per_flow: 4,
            backlog: 2,
            max_flows: 8,
        }
    }

    /// A distinct peer key per byte. The address is derived from it rather
    /// than invented, so a test cannot pair a key with an address the wire
    /// would never have carried together.
    fn key(byte: u8) -> XOnlyPublicKey {
        crate::identity::Identity::from_secret_bytes(&[byte; 32])
            .expect("a non-zero secret is a valid key")
            .pubkey()
    }

    fn peer(byte: u8) -> NodeAddr {
        NodeAddr::from_pubkey(&key(byte))
    }

    fn sink() -> (Sender<Datagram>, mpsc::Receiver<Datagram>) {
        mpsc::channel(16)
    }

    fn arrivals() -> (Sender<Arrival>, mpsc::Receiver<Arrival>) {
        mpsc::channel(16)
    }

    #[test]
    fn a_port_has_one_owner() {
        let mut registry = Registry::new(limits());
        let (tx, _rx) = arrivals();
        registry.listen(Some(4242), tx).unwrap();

        let (tx, _rx) = arrivals();
        assert_eq!(
            registry.listen(Some(4242), tx).unwrap_err(),
            RegistryError::PortTaken(4242)
        );

        // A connected flow may not take a listener's port either: the owner is
        // one or the other, never both.
        let (tx, _rx) = sink();
        assert_eq!(
            registry
                .connect(key(1), 5000, Some(4242), tx, 0)
                .unwrap_err(),
            RegistryError::PortTaken(4242)
        );
    }

    #[test]
    fn a_reserved_port_is_refused_by_the_registry_too() {
        // The command layer refuses these as well. Checking here means a caller
        // that reaches the registry by another route cannot bind the shim's
        // port.
        let mut registry = Registry::new(limits());
        let (tx, _rx) = arrivals();
        assert!(matches!(
            registry.listen(Some(256), tx).unwrap_err(),
            RegistryError::Port(_)
        ));
    }

    #[test]
    fn releasing_a_flow_frees_its_port() {
        let mut registry = Registry::new(limits());
        let (tx, _rx) = sink();
        let (port, _id) = registry.connect(key(1), 5000, Some(4242), tx, 0).unwrap();
        assert_eq!(port, 4242);
        assert_eq!(registry.port_count(), 1);

        registry.release(&FlowKey {
            peer: peer(1),
            remote: 5000,
            local: 4242,
        });
        assert_eq!(registry.port_count(), 0);

        // And the port can be taken again.
        let (tx, _rx) = arrivals();
        assert!(registry.listen(Some(4242), tx).is_ok());
    }

    #[test]
    fn ephemeral_ports_come_from_the_ephemeral_range_and_do_not_repeat() {
        let mut registry = Registry::new(limits());
        let mut seen = Vec::new();
        for _ in 0..4 {
            let (tx, _rx) = sink();
            let (port, _id) = registry.connect(key(1), 5000, None, tx, 0).unwrap();
            assert!(port >= PORT_EPHEMERAL_MIN, "got {port}");
            assert!(!seen.contains(&port), "port {port} handed out twice");
            seen.push(port);
        }
    }

    #[test]
    fn an_established_flow_wins_over_a_listener_on_the_same_port() {
        let mut registry = Registry::new(limits());
        let (arrival_tx, _arrival_rx) = arrivals();
        registry.listen(Some(4242), arrival_tx).unwrap();

        // Announce a peer, accept it, then send again: the second datagram must
        // reach the flow rather than announce the same peer twice.
        let delivery = registry.deliver(peer(7), key(7), 5000, 4242, 0);
        let flow = match delivery {
            Delivery::Arrived(_, arrival) => arrival.flow,
            other => panic!("expected an arrival, got {other:?}"),
        };
        let (tx, _rx) = sink();
        registry.accept(flow, tx, 0).unwrap();

        assert!(matches!(
            registry.deliver(peer(7), key(7), 5000, 4242, 0),
            Delivery::Flow(_)
        ));
    }

    /// The listener is one object and the flows it produced are others, so
    /// closing it must not disturb them and must not let another client take
    /// one over.
    fn accepted_flow_on_a_closed_listener() -> (Registry, mpsc::Receiver<Datagram>) {
        let mut registry = Registry::new(limits());
        let (arrival_tx, _arrival_rx) = arrivals();
        registry.listen(Some(4242), arrival_tx).unwrap();

        let flow = match registry.deliver(peer(7), key(7), 5000, 4242, 0) {
            Delivery::Arrived(_, arrival) => arrival.flow,
            other => panic!("expected an arrival, got {other:?}"),
        };
        let (tx, rx) = sink();
        registry.accept(flow, tx, 0).unwrap();

        registry.release_listener(4242);
        (registry, rx)
    }

    #[test]
    fn a_flow_accepted_from_a_listener_outlives_it_and_keeps_receiving_after_a_rebind() {
        let (mut registry, _rx) = accepted_flow_on_a_closed_listener();

        // The port is bindable again, because the flow never owned it.
        let (arrival_tx, _arrival_rx) = arrivals();
        registry
            .listen(Some(4242), arrival_tx)
            .expect("a closed listener's port is free even while its flows live");

        // The peer that was accepted still reaches its own flow rather than the
        // new listener, which is what keeps two clients' traffic apart.
        assert!(
            matches!(
                registry.deliver(peer(7), key(7), 5000, 4242, 0),
                Delivery::Flow(_)
            ),
            "the surviving flow's key must outrank the new listener's port"
        );

        // And a peer that is new to the port reaches the new listener.
        assert!(matches!(
            registry.deliver(peer(8), key(8), 5001, 4242, 0),
            Delivery::Arrived(_, _)
        ));
    }

    #[test]
    fn a_connect_may_not_take_over_the_key_of_a_flow_that_outlived_its_listener() {
        let (mut registry, mut rx) = accepted_flow_on_a_closed_listener();
        assert_eq!(
            registry.port_count(),
            0,
            "the closed listener gave its port back"
        );

        let (tx, _rx) = sink();
        assert_eq!(
            registry
                .connect(key(7), 5000, Some(4242), tx, 0)
                .unwrap_err(),
            RegistryError::FlowTaken {
                local: 4242,
                remote: 5000
            },
            "a second flow on one key would take the first one's datagrams"
        );

        // The refusal claimed nothing, and the flow it protected still works.
        assert_eq!(registry.port_count(), 0);
        match registry.deliver(peer(7), key(7), 5000, 4242, 0) {
            Delivery::Flow(sink) => sink.try_send(b"still mine".to_vec()).unwrap(),
            other => panic!("expected the surviving flow, got {other:?}"),
        }
        assert_eq!(rx.try_recv().unwrap(), b"still mine".to_vec());
    }

    #[test]
    fn a_different_peer_on_the_same_listener_is_a_separate_flow() {
        let mut registry = Registry::new(limits());
        let (arrival_tx, _arrival_rx) = arrivals();
        registry.listen(Some(4242), arrival_tx).unwrap();

        let first = match registry.deliver(peer(1), key(1), 5000, 4242, 0) {
            Delivery::Arrived(_, arrival) => arrival.flow,
            other => panic!("expected an arrival, got {other:?}"),
        };
        let second = match registry.deliver(peer(2), key(2), 5000, 4242, 0) {
            Delivery::Arrived(_, arrival) => arrival.flow,
            other => panic!("expected an arrival, got {other:?}"),
        };
        assert_ne!(first, second);
    }

    #[test]
    fn an_unowned_port_drops() {
        let mut registry = Registry::new(limits());
        assert!(matches!(
            registry.deliver(peer(1), key(1), 5000, 9999, 0),
            Delivery::Drop(DropCause::NoPort)
        ));
    }

    #[test]
    fn a_full_backlog_drops_rather_than_growing() {
        let mut registry = Registry::new(limits());
        let (arrival_tx, _arrival_rx) = arrivals();
        registry.listen(Some(4242), arrival_tx).unwrap();

        // The backlog is two, so a third distinct peer is refused. Without this
        // an unaccepting client would let any peer grow the node's memory.
        for byte in 1..=2 {
            assert!(matches!(
                registry.deliver(peer(byte), key(byte), 5000, 4242, 0),
                Delivery::Arrived(_, _)
            ));
        }
        assert!(matches!(
            registry.deliver(peer(3), key(3), 5000, 4242, 0),
            Delivery::Drop(DropCause::BacklogFull)
        ));
    }

    #[test]
    fn accepting_returns_what_the_flow_held() {
        let mut registry = Registry::new(limits());
        let (arrival_tx, _arrival_rx) = arrivals();
        registry.listen(Some(4242), arrival_tx).unwrap();

        let flow = match registry.deliver(peer(1), key(1), 5000, 4242, 0) {
            Delivery::Arrived(_, arrival) => arrival.flow,
            other => panic!("expected an arrival, got {other:?}"),
        };
        assert!(registry.hold(flow, b"first".to_vec()));

        let (tx, _rx) = sink();
        let (flow_key, pubkey, held) = registry.accept(flow, tx, 0).unwrap();
        assert_eq!(flow_key.peer, peer(1));
        assert_eq!(
            pubkey,
            key(1),
            "an accepted flow carries the peer's key, not only its wire address"
        );
        assert_eq!(held, vec![b"first".to_vec()]);
    }

    #[test]
    fn a_pending_flow_holds_no_more_than_its_share() {
        let mut registry = Registry::new(limits());
        let (arrival_tx, _arrival_rx) = arrivals();
        registry.listen(Some(4242), arrival_tx).unwrap();
        let flow = match registry.deliver(peer(1), key(1), 5000, 4242, 0) {
            Delivery::Arrived(_, arrival) => arrival.flow,
            other => panic!("expected an arrival, got {other:?}"),
        };

        for _ in 0..limits().per_flow {
            assert!(registry.hold(flow, b"x".to_vec()));
        }
        assert!(!registry.hold(flow, b"x".to_vec()), "the cap should hold");
    }

    #[test]
    fn rejecting_frees_the_backlog_slot() {
        let mut registry = Registry::new(limits());
        let (arrival_tx, _arrival_rx) = arrivals();
        registry.listen(Some(4242), arrival_tx).unwrap();

        let flow = match registry.deliver(peer(1), key(1), 5000, 4242, 0) {
            Delivery::Arrived(_, arrival) => arrival.flow,
            other => panic!("expected an arrival, got {other:?}"),
        };
        registry.reject(flow).unwrap();
        assert_eq!(registry.flow_count(), 0);
        assert_eq!(
            registry.reject(flow).unwrap_err(),
            RegistryError::NoPending(flow)
        );
    }

    #[test]
    fn a_pending_flow_expires_and_a_fresh_one_does_not() {
        let mut registry = Registry::new(limits());
        let (arrival_tx, _arrival_rx) = arrivals();
        registry.listen(Some(4242), arrival_tx).unwrap();
        let flow = match registry.deliver(peer(1), key(1), 5000, 4242, 1_000) {
            Delivery::Arrived(_, arrival) => arrival.flow,
            other => panic!("expected an arrival, got {other:?}"),
        };

        // One millisecond short of the deadline, nothing expires. The healthy
        // path matters as much as the guard: an expiry that fired early would
        // discard flows a client was about to accept.
        assert!(registry.expire(1_000 + PENDING_DEADLINE_MS - 1).is_empty());
        assert_eq!(registry.expire(1_000 + PENDING_DEADLINE_MS), vec![flow]);
        assert_eq!(registry.flow_count(), 0);
    }

    #[test]
    fn releasing_a_listener_takes_its_pending_flows_with_it() {
        let mut registry = Registry::new(limits());
        let (arrival_tx, _arrival_rx) = arrivals();
        registry.listen(Some(4242), arrival_tx).unwrap();
        registry.deliver(peer(1), key(1), 5000, 4242, 0);
        assert_eq!(registry.flow_count(), 1);

        registry.release_listener(4242);
        assert_eq!(registry.flow_count(), 0);
        assert_eq!(registry.port_count(), 0);
    }

    #[test]
    fn the_node_flow_ceiling_holds() {
        let mut registry = Registry::new(limits());
        for _ in 0..limits().max_flows {
            let (tx, _rx) = sink();
            registry.connect(key(1), 5000, None, tx, 0).unwrap();
        }
        let (tx, _rx) = sink();
        assert_eq!(
            registry.connect(key(1), 5000, None, tx, 0).unwrap_err(),
            RegistryError::TooManyFlows(limits().max_flows)
        );
    }

    #[test]
    fn the_flow_view_reports_both_kinds_of_flow_with_their_queue_depth_and_age() {
        let mut registry = Registry::new(limits());
        let (arrival_tx, _arrival_rx) = arrivals();
        registry.listen(Some(4242), arrival_tx).unwrap();

        let (tx, _rx) = sink();
        let (_port, opened) = registry
            .connect(key(1), 5000, Some(6000), tx, 1_000)
            .unwrap();

        let announced = match registry.deliver(peer(2), key(2), 5001, 4242, 2_000) {
            Delivery::Arrived(_, arrival) => arrival.flow,
            other => panic!("expected an arrival, got {other:?}"),
        };
        assert!(registry.hold(announced, b"held".to_vec()));

        let views = registry.flows();
        assert_eq!(views.len(), 2);

        let established = views
            .iter()
            .find(|v| v.flow == opened)
            .expect("opened flow");
        assert!(established.established);
        assert_eq!(established.key.peer, peer(1));
        assert_eq!(established.key.local, 6000);
        assert_eq!(established.key.remote, 5000);
        assert_eq!(established.queued, 0, "nothing has been delivered to it");
        assert_eq!(established.at, 1_000);

        let pending = views
            .iter()
            .find(|v| v.flow == announced)
            .expect("pending flow");
        assert!(!pending.established);
        assert_eq!(pending.key.peer, peer(2));
        assert_eq!(pending.queued, 1, "the held datagram is queued against it");
        assert_eq!(pending.at, 2_000);
    }

    #[test]
    fn an_established_flow_reports_the_datagrams_its_client_has_not_read() {
        let mut registry = Registry::new(limits());
        let (tx, _rx) = sink();
        registry.connect(key(1), 5000, Some(6000), tx, 0).unwrap();

        let flow = FlowKey {
            peer: peer(1),
            remote: 5000,
            local: 6000,
        };
        match registry.deliver(peer(1), key(1), 5000, 6000, 0) {
            Delivery::Flow(sink) => sink.try_send(b"unread".to_vec()).unwrap(),
            other => panic!("expected the established flow, got {other:?}"),
        }

        assert_eq!(registry.flows()[0].queued, 1);
        assert!(registry.release(&flow));
    }

    #[test]
    fn the_listener_view_reports_its_port_and_backlog_depth() {
        let mut registry = Registry::new(limits());
        let (arrival_tx, _arrival_rx) = arrivals();
        registry.listen(Some(4242), arrival_tx).unwrap();
        let (arrival_tx, _arrival_rx) = arrivals();
        registry.listen(Some(4243), arrival_tx).unwrap();

        assert_eq!(
            registry
                .listeners()
                .iter()
                .map(|v| (v.port, v.backlog))
                .collect::<Vec<_>>(),
            vec![(4242, 0), (4243, 0)],
            "ports come out ordered and idle listeners have no backlog"
        );

        registry.deliver(peer(1), key(1), 5000, 4242, 0);
        registry.deliver(peer(2), key(2), 5000, 4242, 0);
        assert_eq!(registry.listeners()[0].backlog, 2);
        assert_eq!(registry.listeners()[1].backlog, 0);
    }

    #[test]
    fn a_listener_that_names_no_port_is_given_an_ephemeral_one_and_told_which() {
        let mut registry = Registry::new(limits());
        let (tx, _rx) = arrivals();
        let port = registry.listen(None, tx).unwrap();
        assert!(
            port >= PORT_EPHEMERAL_MIN,
            "an allocated listener port comes from the ephemeral range, got {port}"
        );

        // The reported port is the one actually held, which is the whole point
        // of reporting it: a listener that answered 0 would leave its client
        // unable to name the port to a peer.
        let (tx, _rx) = arrivals();
        assert_eq!(
            registry.listen(Some(port), tx).unwrap_err(),
            RegistryError::PortTaken(port)
        );
    }

    #[test]
    fn every_flow_reports_the_peers_key_whether_it_was_opened_or_accepted() {
        let mut registry = Registry::new(limits());
        let (tx, _rx) = arrivals();
        registry.listen(Some(4242), tx).unwrap();

        let (tx, _rx) = sink();
        let (_port, opened) = registry.connect(key(1), 5000, Some(6000), tx, 0).unwrap();
        let announced = match registry.deliver(peer(2), key(2), 5001, 4242, 0) {
            Delivery::Arrived(_, arrival) => {
                assert_eq!(arrival.pubkey, key(2), "the announcement names the peer");
                arrival.flow
            }
            other => panic!("expected an arrival, got {other:?}"),
        };

        let views = registry.flows();
        let of = |id: u64| views.iter().find(|v| v.flow == id).expect("flow").pubkey;
        assert_eq!(of(opened), key(1));
        assert_eq!(
            of(announced),
            key(2),
            "a flow learned from the wire reports the same kind of address as one \
             the client opened"
        );
    }
}
