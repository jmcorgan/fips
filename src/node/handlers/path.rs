//! The node's side of each link's path machine (multipath v1 draft):
//! the facts the machine reads about the node's transports, the parameters
//! `node.path` gives it, the path messages it is stepped with, and the
//! executor of what it decides: path messages sent on the path it names,
//! the connections it asks for, a change of active path with its effects,
//! and the disposal of the paths it hands back, closing their connections
//! where the draft says to (Section 5.8); the path tick, which runs the
//! machines' timers while some link has work; and the local transport
//! events the machines hear (Section 3): carrier, interface presence, a
//! transport's removal, and a send to an address that is unreachable.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use fips_core::proto::path::wire::{PathAck, PathClose, PathProbe};
use fips_core::proto::path::{
    Class, Config, Env, Facts, Input, Kind, Medium, Output, Outputs, Params, PathRef, PathState,
    Role, Why,
};
use fips_core::proto::settle::join::Step;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use crate::NodeAddr;
use crate::config::{NodeConfig, PathKind, TransportRole};
use crate::node::settle::exec::{PathSteps, Run, pathed};
use crate::node::{Node, TICK};
use crate::peer::{PeerBundle, PeerInstant, UdpSlot, peer_now};
use crate::transport::{
    ConnectionState, LinkId, TransportAddr, TransportHandle, TransportId, TransportType,
};

/// How often the event loop runs the links' path machines while some link
/// has work: the probes due, their timeouts, the connections a candidate
/// waits for and the connections left to close.
pub(in crate::node) const PATH_TICK: Duration = Duration::from_millis(50);

/// What the node knows about its transports, and whether the peer ACL
/// allows the link's peer, as a link's path machine reads it (draft
/// Section 5.5).
pub(crate) struct NodeFacts<'a> {
    /// The node's transports.
    pub(crate) transports: &'a HashMap<TransportId, TransportHandle>,
    /// Whether the peer ACL now refuses the peer, on every transport and
    /// both ways: the ACL's answer does not depend on who initiates
    /// (`authorize_peer`), so the node would neither accept the peer's
    /// handshake nor initiate one to it.
    pub(crate) denied: bool,
}

impl Facts for NodeFacts<'_> {
    fn mtu(&self, transport: TransportId, addr: &TransportAddr) -> usize {
        self.transports
            .get(&transport)
            .map_or(0, |h| usize::from(h.link_mtu(addr)))
    }

    fn medium(&self, transport: TransportId) -> Medium {
        match self.transports.get(&transport) {
            Some(handle) if is_ble(handle) => Medium::Ble,
            Some(_) | None => Medium::Other,
        }
    }

    fn oriented(&self, transport: TransportId) -> bool {
        self.transports
            .get(&transport)
            .is_some_and(|h| h.transport_type().connection_oriented)
    }

    fn class(&self, transport: TransportId) -> Class {
        self.transports
            .get(&transport)
            .map_or(Class::Clear, |h| class_of(h.transport_type()))
    }

    fn kind(&self, transport: TransportId) -> Option<Kind> {
        let handle = self.transports.get(&transport)?;
        kind_of(handle.transport_type(), handle.kind())
    }

    fn role(&self, transport: TransportId) -> Role {
        self.transports
            .get(&transport)
            .map_or(Role::Normal, |h| role_of(h.role()))
    }

    fn accepts(&self, transport: TransportId) -> bool {
        !self.denied
            && self
                .transports
                .get(&transport)
                .is_some_and(TransportHandle::accept_connections)
    }

    fn dials(&self, transport: TransportId) -> bool {
        // No transport setting at this point forbids dialling a peer the
        // node already holds a link with (draft Section 5.5), but a peer
        // the ACL denies is dialled on no transport.
        !self.denied && self.transports.contains_key(&transport)
    }
}

/// Whether `handle` is a BLE transport, which holds one path per binding
/// (draft Section 5.1).
fn is_ble(handle: &TransportHandle) -> bool {
    #[cfg(ble_available)]
    if matches!(handle, TransportHandle::Ble(_)) {
        return true;
    }
    let _ = handle;
    false
}

/// The anonymity class of a transport of type `ty` (draft Section 3).
pub(crate) fn class_of(ty: &TransportType) -> Class {
    match ty.name {
        "tor" => Class::Tor,
        "nym" => Class::Nym,
        _ => Class::Clear,
    }
}

/// The kind of a transport of type `ty` whose configuration sets the kind
/// `set`: the setting when there is one, which only UDP and TCP take, else
/// the kind the medium fixes, and `None` for UDP, TCP and the loopback,
/// whose paths take the kind of the peer's address (draft Section 5.5).
pub(crate) fn kind_of(ty: &TransportType, set: Option<PathKind>) -> Option<Kind> {
    if let Some(set) = set {
        return Some(match set {
            PathKind::Local => Kind::Local,
            PathKind::Internet => Kind::Internet,
        });
    }
    match ty.name {
        "ethernet" | "wifi" | "ble" | "serial" => Some(Kind::Local),
        "tor" | "nym" => Some(Kind::Internet),
        _ => None,
    }
}

/// The path machine's role for a transport configured with `role`.
pub(crate) fn role_of(role: TransportRole) -> Role {
    match role {
        TransportRole::Never => Role::Never,
        TransportRole::Backup => Role::Backup,
        TransportRole::Normal => Role::Normal,
        TransportRole::Preferred => Role::Preferred,
    }
}

/// The parameters a link's path machine runs with, from `node.path` and
/// the heartbeat interval, which caps the discovery backoff. A configured
/// heartbeat interval below the one-second tick that sends heartbeats runs
/// as the tick, so it maps to the tick. Settings the machine refuses, which
/// validation keeps out of a loaded configuration, fall back to the draft's
/// values with multipath disabled, with a warning once.
pub(crate) fn path_params(node: &NodeConfig) -> Params {
    static WARNED: AtomicBool = AtomicBool::new(false);
    let path = &node.path;
    let cfg = Config {
        enabled: path.enabled,
        switch_margin: path.switch.margin,
        switch_dwell: Duration::from_secs(path.switch.dwell_secs),
        min_samples: u8::try_from(path.min_samples).unwrap_or(0),
        active_interval: Duration::from_millis(path.probe.active_ms),
        standby_interval: Duration::from_millis(path.probe.standby_ms),
        mix_kinds: path.mix_kinds,
        heartbeat: Duration::from_secs(node.heartbeat_interval_secs).max(TICK),
        ..Config::draft()
    };
    Params::new(cfg).unwrap_or_else(|e| {
        if !WARNED.swap(true, Ordering::Relaxed) {
            warn!(error = %e, "Multipath is disabled: the node.path settings are refused");
        }
        let cfg = Config {
            enabled: false,
            ..Config::draft()
        };
        Params::new(cfg).expect("the draft's values are valid")
    })
}

/// A send an encrypt worker gave up on because its destination is
/// unreachable from here: the UDP transport it was sent on and the
/// destination, for the event loop to tell the links' path machines. Only
/// unix starts encrypt workers; elsewhere none is ever made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SendReport {
    /// The sending transport.
    pub transport: TransportId,
    /// The destination the send went to.
    pub dest: SocketAddr,
}

/// A connection a released path held, to close once the step that
/// released it is done (draft Section 5.8).
#[derive(Debug)]
pub(in crate::node) struct Closing {
    /// The local transport.
    transport: TransportId,
    /// The peer's address on it.
    addr: TransportAddr,
    /// The peer.
    node: NodeAddr,
    /// The link whose path was released, which the close rule leaves out
    /// when the drain asks it again.
    link: LinkId,
    /// Whether the peer was removed, which a transport that tracks peers
    /// needs to clear the connection's verification.
    removed: bool,
}

/// The carrier last read on a transport for one link, kept across reads so
/// that a read steps that link only on a loss or a return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Carrier {
    /// Carrier at the last reading.
    Up,
    /// No carrier at the last reading.
    Down,
    /// No carrier at the last reading, and the transport has gone unread
    /// since: the carrier may have come back and gone again meanwhile.
    Lapsed,
}

impl Carrier {
    /// The reading kept for `up`.
    fn read(up: bool) -> Self {
        if up { Self::Up } else { Self::Down }
    }

    /// Whether a reading of `up` after the reading kept, `was`, is a loss or
    /// a return. A first reading of no carrier is a loss and a first reading
    /// of carrier is not a return. After a gap with no carrier kept, every
    /// reading is one: no carrier is a loss the gap may have hidden, and
    /// carrier is a return.
    fn edge(was: Option<Self>, up: bool) -> bool {
        match was {
            None | Some(Self::Up) => !up,
            Some(Self::Down) => up,
            Some(Self::Lapsed) => true,
        }
    }

    /// The reading kept for a link and transport a read leaves out, or `None`
    /// to drop it: a reading of carrier is dropped, so the next reading is a
    /// first one, and a reading of no carrier lapses.
    fn unread(self) -> Option<Self> {
        match self {
            Self::Up => None,
            Self::Down | Self::Lapsed => Some(Self::Lapsed),
        }
    }
}

/// The node's side of the links' path machines.
#[derive(Debug, Default)]
pub(in crate::node) struct PathDriver {
    /// The connections a machine asked for, with the peer whose machine
    /// asked, until they settle.
    connecting: Vec<(NodeAddr, PathRef)>,
    /// The connections released paths held, left to close.
    closing: Vec<Closing>,
    /// No later than the earliest instant at which some link's machine has
    /// work; `None` while none has any.
    wake: Option<PeerInstant>,
    /// The machines the path tick has stepped, for tests.
    #[cfg(test)]
    pub(in crate::node) polls: u64,
    /// The carrier last read for each link on each interface-bound transport
    /// its paths use, to tell a loss or a return from no change at that link.
    /// It goes with the link or the transport.
    carrier: HashMap<(LinkId, TransportId), Carrier>,
    /// The encrypt workers' reports of sends to unreachable addresses,
    /// until the event loop takes the receiver.
    pub(in crate::node) reports: Option<mpsc::Receiver<SendReport>>,
    /// What the node's sources list for each linked peer, as candidates.
    pub(in crate::node) listings: crate::node::handlers::path_intake::Listings,
}

impl PathDriver {
    /// Whether the path tick has anything to do: a machine's wake, a
    /// connection to settle or one to close. A node with multipath disabled
    /// never has any, so its event loop does not run the tick.
    pub(in crate::node) fn armed(&self) -> bool {
        self.wake.is_some() || !self.connecting.is_empty() || !self.closing.is_empty()
    }

    /// Queue the connection at `to`, which a released path of `node`'s link
    /// `link` held, to close once the step that released it is done;
    /// `removed` says the release is part of the peer's removal.
    pub(in crate::node) fn close_later(
        &mut self,
        to: PathRef,
        node: NodeAddr,
        link: LinkId,
        removed: bool,
    ) {
        self.closing.push(Closing {
            transport: to.transport,
            addr: to.addr,
            node,
            link,
            removed,
        });
    }

    /// Record a connection `node`'s machine waits for at `to`, as a
    /// `Connect` does, for tests of the tick's arming.
    #[cfg(test)]
    pub(in crate::node) fn wait(&mut self, node: NodeAddr, to: PathRef) {
        self.connecting.push((node, to));
    }

    /// The addresses on `transport` a connect or a close is waiting on, for
    /// tests that account for every open connection.
    #[cfg(test)]
    pub(in crate::node) fn waiting(&self, transport: TransportId) -> Vec<TransportAddr> {
        let connects = self
            .connecting
            .iter()
            .filter(|(_, to)| to.transport == transport)
            .map(|(_, to)| to.addr.clone());
        let closes = self
            .closing
            .iter()
            .filter(|c| c.transport == transport)
            .map(|c| c.addr.clone());
        connects.chain(closes).collect()
    }

    /// How many carrier readings are kept, for tests of when they go.
    #[cfg(test)]
    pub(in crate::node) fn readings(&self) -> usize {
        self.carrier.len()
    }

    /// The connections waited for on `node`'s behalf, for tests that read a
    /// peer's state whole.
    #[cfg(test)]
    pub(in crate::node) fn connects(&self, node: &NodeAddr) -> Vec<PathRef> {
        self.connecting
            .iter()
            .filter(|(n, _)| n == node)
            .map(|(_, to)| to.clone())
            .collect()
    }

    /// The closes queued for `node`, each as its pair and whether the peer
    /// was removed, for tests that read a peer's state whole.
    #[cfg(test)]
    pub(in crate::node) fn closes(&self, node: &NodeAddr) -> Vec<(PathRef, bool)> {
        self.closing
            .iter()
            .filter(|c| c.node == *node)
            .map(|c| {
                let to = PathRef {
                    transport: c.transport,
                    addr: c.addr.clone(),
                };
                (to, c.removed)
            })
            .collect()
    }

    /// The transports `link` has a carrier reading kept for.
    #[cfg(test)]
    pub(in crate::node) fn carried(&self, link: LinkId) -> Vec<TransportId> {
        let mut kept: Vec<TransportId> = self
            .carrier
            .keys()
            .filter(|(l, _)| *l == link)
            .map(|(_, t)| *t)
            .collect();
        kept.sort_by_key(TransportId::as_u32);
        kept
    }

    /// Keep a no-carrier reading for `link` on `transport`, as a read that
    /// found the carrier gone would, for tests that plant a reading.
    #[cfg(test)]
    pub(in crate::node) fn plant_reading(&mut self, link: LinkId, transport: TransportId) {
        self.carrier.insert((link, transport), Carrier::Down);
    }

    /// Lower the wake to `at`, a machine's next wake, if that is earlier.
    pub(in crate::node) fn fold(&mut self, at: Option<PeerInstant>) {
        if let Some(at) = at {
            self.wake = Some(self.wake.map_or(at, |w| w.min(at)));
        }
    }
}

/// What running one step's outputs did that its caller must know.
#[derive(Debug, Default)]
pub(in crate::node) struct Ran {
    /// The machine was orphaned and its peer removed.
    pub(in crate::node) orphaned: bool,
}

impl Node {
    /// Step the path message `plaintext` (its type byte first) from `from`,
    /// which arrived on `arrival`, into the peer's path machine. A message
    /// that does not decode is dropped. With multipath disabled the machine
    /// takes it as a poll, which answers nothing (draft Section 8.2).
    pub(in crate::node) async fn path_message(
        &mut self,
        from: &NodeAddr,
        plaintext: &[u8],
        arrival: (TransportId, &TransportAddr),
    ) {
        let (transport, addr) = (arrival.0, arrival.1.clone());
        let Some((&ty, body)) = plaintext.split_first() else {
            return;
        };
        // The other end of "Path message sent", so a run's two logs show
        // which direction lost a message. `len` here takes in any padding.
        debug!(
            peer = %self.peer_display_name(from),
            transport_id = %transport,
            remote_addr = %addr,
            msg_type = ty,
            len = plaintext.len(),
            "Path message received"
        );
        let input = match ty {
            0x52 => PathProbe::decode(body).map(|msg| Input::Probe {
                transport,
                addr,
                msg,
            }),
            0x53 => PathAck::decode(body).map(|msg| Input::Ack {
                transport,
                addr,
                msg,
            }),
            _ => PathClose::decode(body).map(|msg| Input::Close {
                transport,
                addr,
                msg,
            }),
        };
        let input = match input {
            Ok(input) => input,
            Err(e) => {
                debug!(
                    peer = %self.peer_display_name(from),
                    msg_type = ty,
                    error = %e,
                    "Path message dropped: it does not decode"
                );
                return;
            }
        };
        if !self.config().node.path.enabled
            && tracing::enabled!(tracing::Level::TRACE)
            && let Some(suppressed) = self.msgtype_budget.admit(Instant::now())
        {
            trace!(
                peer = %self.peer_display_name(from),
                msg_type = ty,
                suppressed,
                "Path message discarded: multipath disabled"
            );
        }
        self.step_path(from, input).await;
    }

    /// Step `input` into `node_addr`'s path machine now, given the link's
    /// measured cost, and carry out what it decides. A peer that is gone
    /// or holds no machine steps nothing.
    pub(in crate::node) async fn step_path(&mut self, node_addr: &NodeAddr, input: Input) -> Ran {
        let why = match input {
            Input::Present { present: false, .. } => "its interface went away",
            Input::Removed { .. } => "its transport was removed",
            _ => "no original or acked path left",
        };
        let denied = self
            .peers
            .get(node_addr)
            .is_some_and(|p| !self.peer_allowed(p.identity()));
        let Some(peer) = self.peers.get_mut(node_addr) else {
            return Ran::default();
        };
        let cost = peer.live_cost();
        let link = self.links.no(&peer.link_id());
        let Some(bundle) = peer.bundle_mut() else {
            return Ran::default();
        };
        let facts = NodeFacts {
            transports: &self.transports,
            denied,
        };
        let mut env = Env {
            facts: &facts,
            cost,
        };
        let out = bundle.step(peer_now(), input, &mut env);
        self.paths.fold(bundle.next_wake());
        let Some(steps) = pathed(*node_addr, out, Some(bundle), link, None) else {
            return Ran::default();
        };
        self.run_outputs(node_addr, steps, why).await
    }

    /// Run the links' path machines' timers (draft Section 5.6): settle the
    /// connections they wait for, step every machine whose next wake is
    /// due, take the wake again from the rest, and close the connections
    /// left to close.
    pub(in crate::node) async fn path_tick(&mut self) {
        self.pathtick_body().await;
        self.audit_live("path_tick");
    }

    /// The work of [`Self::path_tick`], which audits the per-peer maps
    /// after it.
    async fn pathtick_body(&mut self) {
        self.read_carrier().await;
        self.poll_connects().await;
        let now = peer_now();
        if self.paths.wake.is_some_and(|w| w <= now) {
            let due: Vec<NodeAddr> = self
                .peers
                .iter()
                .filter(|(_, p)| wake_of(p.bundle()).is_some_and(|w| w <= now))
                .map(|(addr, _)| *addr)
                .collect();
            for node_addr in due {
                #[cfg(test)]
                {
                    self.paths.polls += 1;
                }
                self.step_path(&node_addr, Input::Poll).await;
            }
            self.paths.wake = self
                .peers
                .values()
                .filter_map(|p| wake_of(p.bundle()))
                .min();
        }
        self.drain_closes().await;
    }

    /// Step each connection a machine waits for that has settled: opened,
    /// or failed, or gone with its transport; one still opening waits for
    /// the next tick. A connection the transport has no attempt for has
    /// failed to start. A connection that opened for a pair the bundle no
    /// longer holds, which a move's renewal can release while the connect
    /// is out, is closed instead, unless another live link uses it.
    async fn poll_connects(&mut self) {
        for (node_addr, to) in std::mem::take(&mut self.paths.connecting) {
            let state = self
                .transports
                .get(&to.transport)
                .map(|t| t.connection_state(&to.addr));
            let ok = match state {
                Some(ConnectionState::Connecting) => {
                    self.paths.connecting.push((node_addr, to));
                    continue;
                }
                Some(ConnectionState::Connected) => true,
                Some(ConnectionState::None | ConnectionState::Failed(_)) | None => false,
            };
            if ok && self.unwanted(&node_addr, &to) {
                if let Some(transport) = self.transports.get(&to.transport) {
                    transport.close_connection(&to.addr).await;
                }
                debug!(
                    peer = %self.peer_display_name(&node_addr),
                    transport_id = %to.transport,
                    remote_addr = %to.addr,
                    "Closed a connection that opened for a path no longer held"
                );
                continue;
            }
            let input = Input::Connected {
                transport: to.transport,
                addr: to.addr,
                ok,
            };
            self.step_path(&node_addr, input).await;
        }
    }

    /// Whether the connection that opened at `to` for `node_addr`'s bundle
    /// is one nothing wants: the bundle no longer holds the pair, and no
    /// live link but the peer's own uses it, by the close rule. A peer no
    /// longer held holds no pair, and its connect is answered by the rule
    /// alone.
    fn unwanted(&self, node_addr: &NodeAddr, to: &PathRef) -> bool {
        let peer = self.peers.get(node_addr);
        let held = peer.is_some_and(|p| {
            !matches!(
                p.path_match(to.transport, &to.addr),
                crate::peer::Match::None
            )
        });
        if node_fault!(ConnectLeftOpen) {
            return false;
        }
        if held && !node_fault!(ConnectClosesHeld) {
            return false;
        }
        // Link ids are numbered from 1, so 0 excepts no link.
        let own = peer.map_or(LinkId::new(0), |p| p.link_id());
        !self.in_use(to.transport, &to.addr, own)
    }

    /// Carry out the outputs of `node_addr`'s path machine, front to back,
    /// then close the connections left to close. Each comes through the
    /// settlement core's join with the core input it stands for after it,
    /// which goes to the core's record of the link. `why` says, for the log,
    /// why an orphaned link's peer is removed.
    async fn run_outputs(
        &mut self,
        node_addr: &NodeAddr,
        steps: PathSteps,
        why: &'static str,
    ) -> Ran {
        let mut ran = Ran::default();
        let link = self.peers.get(node_addr).map(|p| p.link_id());
        for step in steps {
            let output = match step {
                Step::Path(output) => output,
                // An orphaning is acted on as the path output beside it.
                Step::Core(input) => {
                    self.feed(&input);
                    continue;
                }
                Step::Rekey(_) | Step::Replace(_) => {
                    debug_assert!(false, "the join gave a bundle's step a rekey step");
                    continue;
                }
            };
            match output {
                Output::Send { to, bytes } => {
                    match self.send_path(node_addr, &bytes, &to).await {
                        // The first byte is the message type (0x52 probe,
                        // 0x53 ack, 0x54 close) and `len` the encoded
                        // message, before the padding added at send.
                        Ok(()) => debug!(
                            peer = %self.peer_display_name(node_addr),
                            transport_id = %to.transport,
                            remote_addr = %to.addr,
                            msg_type = bytes.first().copied().unwrap_or_default(),
                            len = bytes.len(),
                            "Path message sent"
                        ),
                        Err(e) => debug!(
                            peer = %self.peer_display_name(node_addr),
                            transport_id = %to.transport,
                            remote_addr = %to.addr,
                            error = %e,
                            "Path message not sent"
                        ),
                    }
                }
                Output::Connect { to } => {
                    if let Some(transport) = self.transports.get(&to.transport)
                        && let Err(e) = transport.connect(&to.addr).await
                    {
                        debug!(
                            peer = %self.peer_display_name(node_addr),
                            remote_addr = %to.addr,
                            error = %e,
                            "Path connection not started"
                        );
                    }
                    self.paths.connecting.push((*node_addr, to));
                }
                // Read afresh: an earlier output of this step may have
                // removed the peer.
                Output::Switched { from, to, why } => {
                    if let Some(link) = self.peers.get(node_addr).map(|p| p.link_id()) {
                        let mut run = Run::switched(*node_addr, link, from, to, why);
                        self.run_now(&mut run);
                    }
                }
                Output::Released { to, driver, keep } => match link {
                    Some(link) => self.release_path(node_addr, link, to, driver, keep, false),
                    None => clear_slot(driver),
                },
                Output::Moved { from, to, driver } => {
                    clear_slot(driver);
                    let mut run = Run::followed(*node_addr, link, from, to);
                    self.run_now(&mut run);
                }
                Output::State {
                    to,
                    path_id,
                    from,
                    next,
                    why,
                } => self.log_state(node_addr, &to, path_id, from, next, why),
                Output::Capable => info!(
                    peer = %self.peer_display_name(node_addr),
                    "Peer implements multipath"
                ),
                Output::NotCapable => debug!(
                    peer = %self.peer_display_name(node_addr),
                    "Peer did not answer capability probes; link held not capable"
                ),
                Output::Refused { to, why } => debug!(
                    peer = %self.peer_display_name(node_addr),
                    transport_id = %to.transport,
                    remote_addr = %to.addr,
                    why = ?why,
                    "Path input refused"
                ),
                Output::Orphaned => {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        "Removing peer: {why}"
                    );
                    let why = crate::proto::settle::output::Why::Orphaned;
                    self.route_link_dead(*node_addr, Self::now_ms(), why).await;
                    ran.orphaned = true;
                }
            }
        }
        self.drain_closes().await;
        ran
    }

    /// Log a change of state of `node_addr`'s path `path_id` at `to`.
    fn log_state(
        &self,
        node_addr: &NodeAddr,
        to: &PathRef,
        path_id: u32,
        from: Option<PathState>,
        next: Option<PathState>,
        why: Why,
    ) {
        debug!(
            peer = %self.peer_display_name(node_addr),
            transport_id = %to.transport,
            remote_addr = %to.addr,
            path_id,
            from = ?from,
            next = ?next,
            why = ?why,
            "Path state changed"
        );
    }

    /// Carry out what `node_addr`'s path machine handed back when its link
    /// started again at a won crossed handshake ([`PeerBundle::renew`]):
    /// each path's change of state is logged, and each path released is
    /// disposed of while the link lives. Each comes through the settlement
    /// core's join with the core input it stands for after it, which goes to
    /// the core's record of the link. A move onto the dial's link renews the
    /// bundle on that link and releases the paths of the link it left,
    /// `left`, which the record and the release are then for. The
    /// connections left to close are closed at the next tick.
    pub(in crate::node) fn run_renewed(
        &mut self,
        node_addr: &NodeAddr,
        left: Option<LinkId>,
        out: Outputs<UdpSlot>,
    ) {
        let held = self.peers.get(node_addr).map(|p| p.link_id());
        let no = held.and_then(|link| self.links.no(&link));
        let gone = left.and_then(|link| self.links.no(&link));
        let link = left.or(held);
        let bundle = self.peers.get(node_addr).and_then(|p| p.bundle());
        let steps = pathed(*node_addr, out, bundle, no, gone);
        for step in steps.into_iter().flatten() {
            let output = match step {
                Step::Path(output) => output,
                Step::Core(input) => {
                    self.feed(&input);
                    continue;
                }
                Step::Rekey(_) | Step::Replace(_) => {
                    debug_assert!(false, "the join gave a bundle's step a rekey step");
                    continue;
                }
            };
            match output {
                Output::State {
                    to,
                    path_id,
                    from,
                    next,
                    why,
                } => {
                    if !node_fault!(RenewedStateDropped) {
                        self.log_state(node_addr, &to, path_id, from, next, why);
                    }
                }
                Output::Released { to, driver, keep } => {
                    if let Some(link) = link {
                        self.release_path(node_addr, link, to, driver, keep, false);
                    }
                }
                _ => {}
            }
        }
    }

    /// Dispose of the path `to` of `node_addr`'s link `link`, which its
    /// machine handed back with its driver slot (draft Section 5.8): the
    /// slot's connected UDP socket and its drain go, drain first; then the
    /// release runs through the executor: while the link lives (`removed`
    /// false) its address lookup loses `to`, and unless `keep` says the peer
    /// may still send on it, or another peer's link uses it, the connection
    /// at `to` is queued to close.
    pub(in crate::node) fn release_path(
        &mut self,
        node_addr: &NodeAddr,
        link: LinkId,
        to: PathRef,
        driver: UdpSlot,
        keep: bool,
        removed: bool,
    ) {
        clear_slot(driver);
        let mut run = Run::released(*node_addr, link, to, keep, removed);
        self.run_now(&mut run);
    }

    /// Close every connection a released path left, and on a transport
    /// that tracks peers clear the connection's verification. The close rule
    /// is asked again first, since a link may have taken the connection up
    /// between the release and the drain: a restart's teardown queues its
    /// paths' closes before the new link is promoted at one of their pairs.
    pub(in crate::node) async fn drain_closes(&mut self) {
        for job in std::mem::take(&mut self.paths.closing) {
            if !node_fault!(DrainReadsNothing) && self.in_use(job.transport, &job.addr, job.link) {
                debug!(
                    peer = %self.peer_display_name(&job.node),
                    transport_id = %job.transport,
                    remote_addr = %job.addr,
                    "Kept a released path's connection, which a link now uses"
                );
                continue;
            }
            let Some(transport) = self.transports.get(&job.transport) else {
                continue;
            };
            transport.close_connection(&job.addr).await;
            if transport.tracks_peers() {
                transport
                    .clear_verified(&job.addr, &job.node, job.removed)
                    .await;
            }
            debug!(
                peer = %self.peer_display_name(&job.node),
                transport_id = %job.transport,
                remote_addr = %job.addr,
                "Closed a released path's connection"
            );
        }
    }

    /// Read carrier on the interface-bound transports the paths of links
    /// holding more than one path use, and step each loss and each return
    /// into the link it is one for (draft Section 5.6). The reading is kept
    /// per link, since the rule it serves is about a link: a link that joins
    /// it after another link read a loss sees that loss itself. A first
    /// reading of no carrier is a loss; a first reading of carrier records
    /// it without an edge, so a return that came while a link kept no
    /// reading is not seen. A link and transport no longer read keep a
    /// reading of no carrier, marked as lapsed, and drop a reading of
    /// carrier, so that when they are read again a loss while they were not
    /// read is seen, and so is a return since a loss. A link of one path is
    /// left to the FMP heartbeat, and with multipath disabled no link holds
    /// more than one. Several edges of one link step in its path order, since
    /// that order decides whether the link switches when two carriers go.
    pub(in crate::node) async fn read_carrier(&mut self) {
        let mut used = Vec::new();
        let mut keys = HashSet::new();
        let mut links = HashSet::new();
        for (node_addr, peer) in &self.peers {
            links.insert(peer.link_id());
            if let Some(bundle) = peer.bundle().filter(|b| b.paths().len() > 1) {
                for path in bundle.paths().paths() {
                    let key = (peer.link_id(), path.transport_id());
                    if keys.insert(key) {
                        used.push((key, *node_addr));
                    }
                }
            }
        }
        let transports = &self.transports;
        self.paths.carrier.retain(|key, kept| {
            if keys.contains(key) {
                return true;
            }
            let (link, transport) = key;
            let present = links.contains(link) && transports.contains_key(transport);
            match kept.unread().filter(|_| present) {
                Some(lapsed) => {
                    *kept = lapsed;
                    true
                }
                None => false,
            }
        });
        let mut read: HashMap<TransportId, Option<bool>> = HashMap::new();
        let mut edges = Vec::new();
        for (key, node_addr) in used {
            let transport = key.1;
            let carrier = read.entry(transport).or_insert_with(|| {
                self.transports
                    .get(&transport)
                    .and_then(TransportHandle::interface_presence)
                    .map(|p| p.carrier)
            });
            let Some(up) = *carrier else {
                continue;
            };
            let was = self.paths.carrier.insert(key, Carrier::read(up));
            if Carrier::edge(was, up) {
                edges.push((node_addr, transport, up));
            }
        }
        for (node_addr, transport, up) in edges {
            let held = self.peers.get(&node_addr).is_some_and(|p| {
                p.bundle().is_some_and(|b| b.paths().len() > 1) && p.uses(transport)
            });
            if held {
                self.step_path(&node_addr, Input::Carrier { transport, up })
                    .await;
            }
        }
    }

    /// Tell every link's path machine that the interface of `transport` went
    /// away (`present` false) or came back, and return how many links that
    /// left with no original or acked path, whose peers have been removed
    /// as a link that goes dead is (draft Sections 5.7 and 5.9).
    pub(in crate::node) async fn path_presence(
        &mut self,
        transport: TransportId,
        present: bool,
    ) -> usize {
        let peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
        let mut reaped = 0;
        for node_addr in peers {
            let input = Input::Present { transport, present };
            if self.step_path(&node_addr, input).await.orphaned {
                reaped += 1;
            }
        }
        reaped
    }

    /// Tell every link's path machine that `transport` is being removed, so
    /// that each discards its paths on it before it goes. A link left with
    /// no original or acked path is removed as one that goes dead is.
    pub(in crate::node) async fn path_removed(&mut self, transport: TransportId) {
        let peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
        for node_addr in peers {
            self.step_path(&node_addr, Input::Removed { transport })
                .await;
        }
    }

    /// A send of `node_addr`'s link to `to` failed because the address is
    /// unreachable: tell the link's path machine (draft Section 5.6), when
    /// the link holds more than one path. A link of one path is left to the
    /// FMP heartbeat.
    pub(in crate::node) async fn send_unreachable(&mut self, node_addr: &NodeAddr, to: PathRef) {
        let several = self
            .peers
            .get(node_addr)
            .and_then(|p| p.bundle())
            .is_some_and(|b| b.paths().len() > 1);
        if several {
            let input = Input::SendFailed {
                transport: to.transport,
                addr: to.addr,
            };
            self.step_path(node_addr, input).await;
        }
    }

    /// An encrypt worker gave up on a send on `transport` to `dest` because
    /// the address is unreachable: tell every link holding more than one
    /// path and holding that pair. A report that matches no such link is
    /// dropped. A path whose address is still the hostname form it was
    /// dialled at matches no report until a frame of the peer moves it to
    /// the numeric form; only a node with multipath enabled holds paths a
    /// report could concern.
    pub(in crate::node) async fn path_unreachable(
        &mut self,
        transport: TransportId,
        dest: SocketAddr,
    ) {
        let addr = TransportAddr::from_string(&dest.to_string());
        let held: Vec<NodeAddr> = self
            .peers
            .iter()
            .filter(|(_, p)| {
                p.bundle().is_some_and(|b| {
                    b.paths().len() > 1 && b.paths().find(transport, &addr).is_some()
                })
            })
            .map(|(node_addr, _)| *node_addr)
            .collect();
        if held.is_empty() {
            trace!(
                transport_id = %transport,
                remote_addr = %addr,
                "Unreachable send report matches no path"
            );
        }
        for node_addr in held {
            let to = PathRef {
                transport,
                addr: addr.clone(),
            };
            self.send_unreachable(&node_addr, to).await;
        }
    }

    /// The peer on the link `from` moved onto the link `to`: its carrier
    /// readings are kept, under `to`.
    pub(in crate::node) fn rekey_carrier(&mut self, from: LinkId, to: LinkId) {
        let keys: Vec<(LinkId, TransportId)> = self
            .paths
            .carrier
            .keys()
            .filter(|(link, _)| *link == from)
            .copied()
            .collect();
        for key in keys {
            if let Some(reading) = self.paths.carrier.remove(&key) {
                self.paths.carrier.insert((to, key.1), reading);
            }
        }
    }

    /// Forget the connections `node_addr`'s machine was waiting for, as the
    /// peer is removed.
    pub(in crate::node) fn forget_connects(&mut self, node_addr: &NodeAddr) {
        self.paths.connecting.retain(|(node, _)| node != node_addr);
    }

    /// Offer (`transport`, `addr`) to `peer`'s path machine as a candidate
    /// from configuration, for tests until candidates have a source.
    #[cfg(test)]
    pub(in crate::node) async fn offer_path(
        &mut self,
        peer: &NodeAddr,
        transport: TransportId,
        addr: TransportAddr,
    ) {
        let input = Input::Candidate {
            transport,
            addr,
            source: fips_core::proto::path::Source::Config,
        };
        self.step_path(peer, input).await;
    }
}

/// The kernel's link events, which the carrier read follows between path
/// ticks: on unix, a watcher opened when multipath is enabled.
#[cfg(unix)]
pub(in crate::node) type CarrierWatch = Option<crate::transport::watcher::LinkWatcher>;

/// The kernel's link events, which no platform but unix reports here.
#[cfg(not(unix))]
pub(in crate::node) type CarrierWatch = Option<std::convert::Infallible>;

/// Open the link-event watcher for carrier when multipath is `enabled`. A
/// node with multipath disabled opens none.
pub(in crate::node) fn carrier_watch(enabled: bool) -> CarrierWatch {
    #[cfg(unix)]
    return enabled.then(crate::transport::watcher::LinkWatcher::new);
    #[cfg(not(unix))]
    {
        let _ = enabled;
        None
    }
}

/// Resolve when `watch` reports a link change; never without a watcher.
pub(in crate::node) async fn changed(watch: &CarrierWatch) {
    match watch {
        #[cfg(unix)]
        Some(watcher) => watcher.changed().await,
        #[cfg(not(unix))]
        Some(never) => match *never {},
        None => std::future::pending().await,
    }
}

/// The next wake of `bundle`, if the peer holds one.
fn wake_of(bundle: Option<&PeerBundle>) -> Option<PeerInstant> {
    bundle.and_then(PeerBundle::next_wake)
}

/// Drop a released or moved path's connected UDP socket and its drain,
/// drain first.
fn clear_slot(driver: UdpSlot) {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut driver = driver;
        driver.clear_connected_udp();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = driver;
}
