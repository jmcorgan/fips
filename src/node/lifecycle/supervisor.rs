//! Node lifecycle supervisor — sans-IO core (Milestone-1 Step 1a).
//!
//! A synchronous `step(event) -> Vec<Action>` finite-state machine over the
//! fixed set of substrate children. It owns the *decision* of what to bring up
//! and tear down and in what order; the async driver in [`super`]
//! (`start()`/`stop()`) performs the actual I/O each [`Action`] names and reports
//! results back as [`Event`]s. The core reads no clock, performs no I/O, and
//! holds no runtime handles — time enters only as inputs (a future `Tick`/
//! `DrainDeadlineElapsed`, added with the `Draining` phase) — so it is
//! unit-testable with synthetic sequences and survives a later thread-boundary
//! move (design doc §6 Core 1, §8 "cores are sans-IO").
//!
//! ## Scope: the behavior-neutral rewrite
//!
//! This is the first of the three Step-1a commits and is strictly
//! behavior-preserving. The machine mirrors today's `start()`/`stop()` exactly:
//!
//! - every configured child is spawned in the current order, and optional
//!   failures are warn/debug-and-continue (there is no `Degraded` yet — a
//!   failed child simply drains from `pending` and start still reaches
//!   `Running`, as today an even-zero-transport node does);
//! - teardown runs in today's order and, faithfully, does **not** stop the
//!   encrypt/decrypt worker pools (they are spawned in `start()` but never torn
//!   down in `stop()`);
//! - the machine authors only the `SpawnChild`/`StopChild` *ordering*, and the
//!   driver keeps its `self.state` writes at their current positions. The
//!   behavior-neutral relocation left the published `NodeState` transitions
//!   byte-for-byte unchanged; the bounded-drain phase below adds exactly one new
//!   published transition (`Draining`), written directly like the others.
//!
//! ## Scope: the bounded `Draining` phase (this commit)
//!
//! This commit adds the operator-visible bounded-drain additions and nothing
//! else: the [`SupState::Draining`] state, the [`Event::Drain`] /
//! [`Event::DrainDeadlineElapsed`] events, the drain [`Action`]s
//! ([`Action::BroadcastDisconnect`], [`Action::SetTimer`],
//! [`Action::SetPeeringDesired`], [`Action::SuspendReplenish`]), and the new
//! published [`NodeState::Draining`](crate::node::NodeState::Draining) —
//! written directly by the driver at drain entry, exactly like the other
//! `self.state` transitions this milestone uses. The existing immediate `Stop`
//! path is untouched. `Draining` and `Stop` share a single teardown-plan author
//! (`begin_stopping`), so the teardown ordering is defined once.
//!
//! What is deferred is only the FSM-owned `PublishState` *action* (published
//! state authored by the machine rather than the driver): it lands with the
//! `Running{Full|Degraded}` health split (design doc §6/§9.1), which needs it
//! because a single direct `self.state` write cannot express the health fork.
//! The `Draining` published state itself is **not** deferred — it is here.

use std::collections::HashSet;
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::node::NodeState;
use crate::transport::{PacketTx, TransportId};
use crate::upper::tun::{TunOutboundRx, TunTx};

/// A supervised substrate child (design doc §6 Core 1).
///
/// Each transport is an individual child keyed by its id so the later
/// required-vs-optional health policy can reason about partial N-of-M bring-up.
/// The TUN device is a compound unit at the driver (a reader thread plus a
/// writer thread); the supervisor tracks it as the single `Tun` child, and the
/// driver joins both threads when it executes `StopChild(Tun)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Child {
    /// A transport instance (UDP / TCP / Ethernet), keyed by its runtime id.
    Transport(TransportId),
    /// The off-task FMP-encrypt + UDP-send worker pool (`#[cfg(unix)]`).
    EncryptWorkers,
    /// The off-task FMP-decrypt worker pool (`#[cfg(unix)]`).
    DecryptWorkers,
    /// Nostr overlay rendezvous/discovery.
    Nostr,
    /// LAN mDNS / DNS-SD rendezvous.
    Mdns,
    /// The TUN device (reader + writer threads).
    Tun,
    /// The `.fips` DNS responder task.
    Dns,
}

/// An input to the supervisor. Results of executing [`Action`]s are fed back as
/// `SubstrateUp` / `SubstrateFailed` / `ChildStopped`.
///
/// `Tick` and `ChildExited` (design doc §6) arrive with the `Degraded`/health
/// commit; the bounded-drain events (`Drain` / `DrainDeadlineElapsed`) are
/// present here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    /// Begin bring-up. `transports` are the ids the driver has already created
    /// (their ids are allocated at creation), in creation order; the booleans
    /// mark which singleton children are configured. Valid from `Created` or
    /// `Stopped`.
    Start {
        /// Created transport ids, in the order they must be started.
        transports: Vec<TransportId>,
        /// The `#[cfg(unix)]` encrypt worker pool is configured.
        encrypt_workers: bool,
        /// The `#[cfg(unix)]` decrypt worker pool is configured.
        decrypt_workers: bool,
        /// Nostr overlay discovery is enabled.
        nostr: bool,
        /// LAN mDNS discovery is enabled.
        mdns: bool,
        /// The TUN device is enabled.
        tun: bool,
        /// The DNS responder is enabled.
        dns: bool,
    },
    /// A child the driver was asked to spawn came up.
    SubstrateUp {
        /// The child that started successfully.
        child: Child,
    },
    /// A child the driver was asked to spawn failed to start. In the
    /// behavior-neutral rewrite this is warn/debug-and-continue: the child
    /// drains from `pending` and never joins the up-set (matching today), and
    /// start still proceeds to `Running`.
    SubstrateFailed {
        /// The child that failed to start.
        child: Child,
    },
    /// Begin an immediate teardown (no drain). Valid from `Running`. This is
    /// the path `node.stop()` uses; unchanged from the behavior-neutral rewrite.
    Stop,
    /// Begin a bounded graceful drain. Valid from `Running`. Emits the drain
    /// entry actions (broadcast Disconnect, arm the deadline timer, gate the
    /// reconciler off) and moves to `Draining`; the driver then runs the
    /// bounded drain window before feeding `DrainDeadlineElapsed`.
    Drain {
        /// Absolute drain deadline in driver-clock milliseconds, carried into
        /// `Draining` and the `SetTimer` action for observability. The driver
        /// owns the actual bounded wait.
        deadline_ms: u64,
    },
    /// The bounded drain window has closed — either the deadline elapsed or all
    /// peers drained early. Valid from `Draining`; begins the (shared) teardown
    /// plan, transitioning to `Stopping`.
    DrainDeadlineElapsed,
    /// A child the driver was asked to stop has finished stopping.
    ChildStopped {
        /// The child that has been torn down.
        child: Child,
    },
}

/// A driver-scheduled timer the supervisor can arm (design doc §6). Only the
/// drain deadline exists for now; the handshake/rekey/liveness timers named in
/// §8 arrive with later cores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Timer {
    /// Fires when the bounded drain window closes. The driver feeds
    /// [`Event::DrainDeadlineElapsed`] when it elapses (or earlier, when all
    /// peers have drained).
    DrainDeadline,
}

/// The reconciler's desired peering set (design doc §8 drain gate). Only
/// `Empty` is needed in this commit; the populated variants that the Step-1b
/// homeostatic reconciler converges toward land with that core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PeeringDesired {
    /// No peers desired. Entering `Draining` sets this so the reconciler stops
    /// reconnecting the peers the drain just closed (§8: "Draining switches the
    /// homeostat off").
    Empty,
}

/// An effect the driver must perform. The core never performs I/O itself.
///
/// `PublishState` (design doc §6) is intentionally absent until the
/// `Running{Full|Degraded}` health commit: the driver keeps its verbatim
/// `self.state` writes, so no published-state action is needed yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Bring up this child (the driver performs the spawn / start I/O and
    /// reports `SubstrateUp` or `SubstrateFailed`).
    SpawnChild(Child),
    /// Tear down this child (the driver performs the stop / join I/O and
    /// reports `ChildStopped`).
    StopChild(Child),
    /// Broadcast a shutdown `Disconnect` to all sendable peers. Emitted once,
    /// at drain entry; the drain teardown does not re-broadcast.
    BroadcastDisconnect,
    /// Arm a driver timer at the given absolute driver-clock milliseconds. In
    /// this commit only `DrainDeadline` exists; the driver notes the deadline
    /// and owns the bounded drain wait, so this is a documented no-op beyond
    /// bookkeeping.
    SetTimer(Timer, u64),
    /// Set the reconciler's desired peering set (§8 drain gate). Documented
    /// **no-op in this commit** — the reconciler that consumes it lands in
    /// Step 1b; the driver logs/ignores it for now.
    SetPeeringDesired(PeeringDesired),
    /// Suspend peer replenishment (§8 drain gate). Documented **no-op in this
    /// commit** for the same reason as `SetPeeringDesired`.
    SuspendReplenish,
}

/// Internal supervisor state (design doc §6). Richer than the published
/// [`NodeState`](crate::node::NodeState): `Starting`/`Stopping` carry the set of
/// children still resolving. `Draining{deadline}`, `Running{Full|Degraded}`, and
/// `Failed{reason}` are added by the later flagged commits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SupState {
    /// Constructed but not started.
    Created,
    /// Bringing children up; `pending` is the set not yet resolved.
    Starting {
        /// Children asked to spawn that have not yet reported up-or-failed.
        pending: HashSet<Child>,
    },
    /// All children resolved; node operational.
    Running,
    /// Bounded graceful-drain window (design doc §6/§8). Broadcast Disconnect
    /// has gone out and the reconciler is gated off (desired peering set
    /// emptied, replenishment suspended); teardown begins when
    /// `DrainDeadlineElapsed` arrives. Logically sits between `Running` and
    /// `Stopping`.
    Draining {
        /// Absolute drain deadline in driver-clock milliseconds (carried for
        /// observability; the driver owns the actual wait).
        deadline_ms: u64,
    },
    /// Tearing children down; `pending` is the set not yet stopped.
    Stopping {
        /// Children asked to stop that have not yet reported stopped.
        pending: HashSet<Child>,
    },
    /// Fully torn down.
    Stopped,
}

/// The lifecycle supervisor FSM.
///
/// Construct with [`SupervisorFsm::new`], feed [`Event`]s via [`SupervisorFsm::step`],
/// and execute the returned [`Action`]s. See the module docs for the
/// behavior-neutral scope.
#[derive(Clone, Debug)]
pub(crate) struct SupervisorFsm {
    state: SupState,
    /// Children currently up (present). Drives the teardown plan.
    up: HashSet<Child>,
}

impl SupervisorFsm {
    /// A fresh supervisor in `Created`.
    pub(crate) fn new() -> Self {
        Self {
            state: SupState::Created,
            up: HashSet::new(),
        }
    }

    /// A supervisor seeded directly into `Running` with a known up-set.
    ///
    /// The teardown driver (`stop()`) reconstructs the up-set from observed
    /// runtime presence (`dns_task.is_some()`, transports keys, etc.) rather
    /// than relying on a live machine persisted across start/stop, so that
    /// teardown ordering is authored here regardless of how the node reached
    /// `Running`. Feeding `Event::Stop` then yields the ordered `StopChild`
    /// plan over exactly the present children.
    pub(crate) fn running_with(up: impl IntoIterator<Item = Child>) -> Self {
        Self {
            state: SupState::Running,
            up: up.into_iter().collect(),
        }
    }

    /// Current internal state (for the driver's bookkeeping and for tests).
    #[cfg(test)]
    pub(crate) fn state(&self) -> &SupState {
        &self.state
    }

    /// Whether the machine is in the bounded-drain window. The driver uses this
    /// after the rx loop returns to decide between the drain-teardown path and
    /// the immediate-`stop()` fallback.
    pub(crate) fn is_draining(&self) -> bool {
        matches!(self.state, SupState::Draining { .. })
    }

    /// Advance the machine by one event, returning the effects to perform.
    pub(crate) fn step(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::Start {
                transports,
                encrypt_workers,
                decrypt_workers,
                nostr,
                mdns,
                tun,
                dns,
            } => self.on_start(
                transports,
                encrypt_workers,
                decrypt_workers,
                nostr,
                mdns,
                tun,
                dns,
            ),
            Event::SubstrateUp { child } => self.on_substrate_up(child),
            Event::SubstrateFailed { child } => self.on_substrate_failed(child),
            Event::Stop => self.on_stop(),
            Event::Drain { deadline_ms } => self.on_drain(deadline_ms),
            Event::DrainDeadlineElapsed => self.on_drain_deadline_elapsed(),
            Event::ChildStopped { child } => self.on_child_stopped(child),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_start(
        &mut self,
        transports: Vec<TransportId>,
        encrypt_workers: bool,
        decrypt_workers: bool,
        nostr: bool,
        mdns: bool,
        tun: bool,
        dns: bool,
    ) -> Vec<Action> {
        // Only meaningful from a not-running state (the driver also guards on
        // `can_start`). Ignore otherwise.
        if !matches!(self.state, SupState::Created | SupState::Stopped) {
            return Vec::new();
        }

        // Canonical spawn order, mirroring today's `start()`:
        // transports (creation order) → encrypt → decrypt → nostr → mdns →
        // tun → dns. (The driver performs the peer-connect between mdns and
        // tun; it is not a supervised child.)
        let mut order: Vec<Child> = transports.into_iter().map(Child::Transport).collect();
        if encrypt_workers {
            order.push(Child::EncryptWorkers);
        }
        if decrypt_workers {
            order.push(Child::DecryptWorkers);
        }
        if nostr {
            order.push(Child::Nostr);
        }
        if mdns {
            order.push(Child::Mdns);
        }
        if tun {
            order.push(Child::Tun);
        }
        if dns {
            order.push(Child::Dns);
        }

        self.up.clear();

        // A node with no children at all still reaches `Running` (today: even
        // zero started transports proceeds to `Running`).
        if order.is_empty() {
            self.state = SupState::Running;
            return Vec::new();
        }

        self.state = SupState::Starting {
            pending: order.iter().copied().collect(),
        };
        order.into_iter().map(Action::SpawnChild).collect()
    }

    fn on_substrate_up(&mut self, child: Child) -> Vec<Action> {
        if let SupState::Starting { pending } = &mut self.state {
            pending.remove(&child);
            self.up.insert(child);
            if pending.is_empty() {
                self.state = SupState::Running;
            }
        }
        Vec::new()
    }

    fn on_substrate_failed(&mut self, child: Child) -> Vec<Action> {
        // Behavior-neutral: warn/continue. The child drains from `pending` and
        // does not join the up-set; start still reaches `Running`.
        if let SupState::Starting { pending } = &mut self.state {
            pending.remove(&child);
            if pending.is_empty() {
                self.state = SupState::Running;
            }
        }
        Vec::new()
    }

    fn on_stop(&mut self) -> Vec<Action> {
        if !matches!(self.state, SupState::Running) {
            return Vec::new();
        }
        self.begin_stopping()
    }

    fn on_drain(&mut self, deadline_ms: u64) -> Vec<Action> {
        // Only a graceful drain from a running node. Inert otherwise (matching
        // `Stop`'s guard).
        if !matches!(self.state, SupState::Running) {
            return Vec::new();
        }
        self.state = SupState::Draining { deadline_ms };
        // Drain entry, in order: broadcast the shutdown Disconnect, arm the
        // deadline timer, then gate the reconciler off (desired = ∅, suspend
        // replenishment) so it cannot reconnect the peers the drain just closed
        // (§8). The up-set is left intact for the eventual teardown plan.
        vec![
            Action::BroadcastDisconnect,
            Action::SetTimer(Timer::DrainDeadline, deadline_ms),
            Action::SetPeeringDesired(PeeringDesired::Empty),
            Action::SuspendReplenish,
        ]
    }

    fn on_drain_deadline_elapsed(&mut self) -> Vec<Action> {
        // The bounded drain window closed (deadline or all-peers-gone). Author
        // the same teardown plan `Stop` produces.
        if !matches!(self.state, SupState::Draining { .. }) {
            return Vec::new();
        }
        self.begin_stopping()
    }

    /// Author the teardown plan over the current up-set, transition to
    /// `Stopping`, and return the ordered `StopChild` actions. Shared by the
    /// immediate `Stop` path ([`Self::on_stop`]) and the drain-window-close path
    /// ([`Self::on_drain_deadline_elapsed`]) so the teardown ordering is defined
    /// exactly once.
    fn begin_stopping(&mut self) -> Vec<Action> {
        let order = self.teardown_order();
        self.state = SupState::Stopping {
            pending: order.iter().copied().collect(),
        };
        order.into_iter().map(Action::StopChild).collect()
    }

    fn on_child_stopped(&mut self, child: Child) -> Vec<Action> {
        if let SupState::Stopping { pending } = &mut self.state {
            pending.remove(&child);
            self.up.remove(&child);
            if pending.is_empty() {
                self.state = SupState::Stopped;
            }
        }
        Vec::new()
    }

    /// Teardown order over the up-set, mirroring today's `stop()`:
    /// dns → nostr → mdns → transports (ascending id) → tun.
    ///
    /// The encrypt/decrypt worker pools are deliberately excluded: today's
    /// `stop()` spawns them in `start()` but never tears them down. Transports
    /// are ordered by ascending id for determinism (today's `stop()` iterates
    /// them in nondeterministic `HashMap` order, so this is neutral).
    fn teardown_order(&self) -> Vec<Child> {
        let mut order = Vec::new();
        if self.up.contains(&Child::Dns) {
            order.push(Child::Dns);
        }
        if self.up.contains(&Child::Nostr) {
            order.push(Child::Nostr);
        }
        if self.up.contains(&Child::Mdns) {
            order.push(Child::Mdns);
        }
        let mut transports: Vec<TransportId> = self
            .up
            .iter()
            .filter_map(|c| match c {
                Child::Transport(id) => Some(*id),
                _ => None,
            })
            .collect();
        transports.sort_by_key(|id| id.as_u32());
        order.extend(transports.into_iter().map(Child::Transport));
        if self.up.contains(&Child::Tun) {
            order.push(Child::Tun);
        }
        order
    }
}

/// Owner of the node's lifecycle-managed substrate handles plus the sans-IO
/// [`SupervisorFsm`] that authors their spawn/teardown ordering.
///
/// The fields moved here off `Node` are exactly the children the supervisor
/// governs — the packet-send channel, the TUN reader/writer plumbing, the DNS
/// responder task, the Nostr/LAN rendezvous drivers, and (on unix) the
/// encrypt/decrypt worker pools — together with the published `NodeState`.
/// This is a pure relocation: the driver (`start()`/`stop()`) reaches each
/// field through `self.supervisor.*`, and the initializers are the same ones
/// `Node::new` used.
pub(crate) struct Supervisor {
    /// Node operational state (the published `NodeState`; the driver keeps its
    /// verbatim writes here at their current positions).
    pub(in crate::node) state: NodeState,

    /// Packet sender for transports.
    pub(in crate::node) packet_tx: Option<PacketTx>,

    /// TUN packet sender channel.
    pub(in crate::node) tun_tx: Option<TunTx>,
    /// Receiver for outbound packets from the TUN reader.
    pub(in crate::node) tun_outbound_rx: Option<TunOutboundRx>,
    /// TUN reader thread handle.
    pub(in crate::node) tun_reader_handle: Option<JoinHandle<()>>,
    /// TUN writer thread handle.
    pub(in crate::node) tun_writer_handle: Option<JoinHandle<()>>,
    /// Shutdown pipe: writing to this fd unblocks the TUN reader thread on macOS.
    /// On Linux, deleting the interface via netlink serves the same purpose.
    #[cfg(target_os = "macos")]
    pub(in crate::node) tun_shutdown_fd: Option<std::os::unix::io::RawFd>,

    /// Receiver for resolved identities from the DNS responder.
    pub(in crate::node) dns_identity_rx: Option<crate::upper::dns::DnsIdentityRx>,
    /// DNS responder task handle.
    pub(in crate::node) dns_task: Option<tokio::task::JoinHandle<()>>,

    /// Node-side driver state for the Nostr overlay peer-rendezvous
    /// subsystem: the engine handle, its startup timestamp, the one-shot
    /// startup-sweep latch, and the per-peer bootstrap-transport bookkeeping
    /// adopted from NAT-traversal handoffs.
    pub(in crate::node) nostr_rendezvous: crate::nostr::RendezvousDriver,
    /// mDNS / DNS-SD responder + browser for local-link peer discovery.
    /// Identity is unverified at this layer — the Noise XX handshake
    /// initiated against an mDNS-observed endpoint is what proves the
    /// peer holds the matching private key.
    pub(in crate::node) lan_rendezvous: Option<Arc<crate::mdns::LanRendezvous>>,

    /// Off-task FMP-encrypt + UDP-send worker pool. Unix-only —
    /// the worker issues direct sendmmsg(2) / sendmsg+UDP_GSO calls
    /// on raw fds via `AsRawFd`. None on Windows or when the worker
    /// pool failed to spawn.
    #[cfg(unix)]
    pub(crate) encrypt_workers: Option<crate::node::encrypt_worker::EncryptWorkerPool>,

    /// Off-task FMP decrypt worker pool — receiver-side mirror of
    /// `encrypt_workers`. Workers are shards: each owns its session
    /// state directly in a thread-local `HashMap` (no `RwLock`,
    /// no `Mutex` per packet). Hash-by-cache-key dispatch.
    #[cfg(unix)]
    pub(crate) decrypt_workers: Option<crate::node::decrypt_worker::DecryptWorkerPool>,

    /// The sans-IO lifecycle FSM authoring spawn/teardown ordering.
    pub(in crate::node) fsm: SupervisorFsm,
}

impl Supervisor {
    /// A fresh supervisor with all handles empty and the FSM in `Created`,
    /// matching the field initializers `Node::new` previously used.
    pub(crate) fn new() -> Self {
        Self {
            state: NodeState::Created,
            packet_tx: None,
            tun_tx: None,
            tun_outbound_rx: None,
            tun_reader_handle: None,
            tun_writer_handle: None,
            #[cfg(target_os = "macos")]
            tun_shutdown_fd: None,
            dns_identity_rx: None,
            dns_task: None,
            nostr_rendezvous: crate::nostr::RendezvousDriver::default(),
            lan_rendezvous: None,
            #[cfg(unix)]
            encrypt_workers: None,
            #[cfg(unix)]
            decrypt_workers: None,
            fsm: SupervisorFsm::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(n: u32) -> TransportId {
        TransportId::new(n)
    }

    fn start_full() -> Event {
        Event::Start {
            transports: vec![tid(1), tid(2)],
            encrypt_workers: true,
            decrypt_workers: true,
            nostr: true,
            mdns: true,
            tun: true,
            dns: true,
        }
    }

    #[test]
    fn start_emits_spawn_in_canonical_order() {
        let mut s = SupervisorFsm::new();
        let actions = s.step(start_full());
        assert_eq!(
            actions,
            vec![
                Action::SpawnChild(Child::Transport(tid(1))),
                Action::SpawnChild(Child::Transport(tid(2))),
                Action::SpawnChild(Child::EncryptWorkers),
                Action::SpawnChild(Child::DecryptWorkers),
                Action::SpawnChild(Child::Nostr),
                Action::SpawnChild(Child::Mdns),
                Action::SpawnChild(Child::Tun),
                Action::SpawnChild(Child::Dns),
            ]
        );
        assert!(matches!(s.state(), SupState::Starting { .. }));
    }

    #[test]
    fn all_children_up_reaches_running() {
        let mut s = SupervisorFsm::new();
        let spawns = s.step(start_full());
        for a in spawns {
            let child = match a {
                Action::SpawnChild(c) => c,
                _ => panic!("unexpected action"),
            };
            assert_eq!(s.step(Event::SubstrateUp { child }), vec![]);
        }
        assert_eq!(s.state(), &SupState::Running);
    }

    #[test]
    fn failed_child_still_reaches_running_and_is_not_up() {
        // Behavior-neutral: a failed optional child does not block Running and
        // is excluded from teardown (never joined the up-set).
        let mut s = SupervisorFsm::new();
        s.step(start_full());
        for child in [
            Child::Transport(tid(1)),
            Child::Transport(tid(2)),
            Child::EncryptWorkers,
            Child::DecryptWorkers,
            Child::Nostr,
        ] {
            s.step(Event::SubstrateUp { child });
        }
        // mdns fails, tun+dns come up
        s.step(Event::SubstrateFailed { child: Child::Mdns });
        s.step(Event::SubstrateUp { child: Child::Tun });
        s.step(Event::SubstrateUp { child: Child::Dns });
        assert_eq!(s.state(), &SupState::Running);

        let stops = s.step(Event::Stop);
        // mdns must not appear in teardown; workers excluded by design.
        assert_eq!(
            stops,
            vec![
                Action::StopChild(Child::Dns),
                Action::StopChild(Child::Nostr),
                Action::StopChild(Child::Transport(tid(1))),
                Action::StopChild(Child::Transport(tid(2))),
                Action::StopChild(Child::Tun),
            ]
        );
    }

    #[test]
    fn no_children_reaches_running_immediately() {
        let mut s = SupervisorFsm::new();
        let actions = s.step(Event::Start {
            transports: vec![],
            encrypt_workers: false,
            decrypt_workers: false,
            nostr: false,
            mdns: false,
            tun: false,
            dns: false,
        });
        assert_eq!(actions, vec![]);
        assert_eq!(s.state(), &SupState::Running);
    }

    #[test]
    fn stop_teardown_order_excludes_workers() {
        let mut s = SupervisorFsm::new();
        s.step(start_full());
        for child in [
            Child::Transport(tid(2)),
            Child::Transport(tid(1)),
            Child::EncryptWorkers,
            Child::DecryptWorkers,
            Child::Nostr,
            Child::Mdns,
            Child::Tun,
            Child::Dns,
        ] {
            s.step(Event::SubstrateUp { child });
        }
        let stops = s.step(Event::Stop);
        assert_eq!(
            stops,
            vec![
                Action::StopChild(Child::Dns),
                Action::StopChild(Child::Nostr),
                Action::StopChild(Child::Mdns),
                // transports ascending by id regardless of up-report order
                Action::StopChild(Child::Transport(tid(1))),
                Action::StopChild(Child::Transport(tid(2))),
                Action::StopChild(Child::Tun),
            ]
        );
        assert!(matches!(s.state(), SupState::Stopping { .. }));
    }

    #[test]
    fn all_children_stopped_reaches_stopped() {
        let mut s = SupervisorFsm::new();
        s.step(start_full());
        // Every spawned child reports an outcome: five come up, three fail
        // (warn/continue). `pending` drains fully, so the node still reaches
        // `Running` — as it does today.
        for child in [
            Child::Transport(tid(1)),
            Child::EncryptWorkers,
            Child::Nostr,
            Child::Tun,
            Child::Dns,
        ] {
            s.step(Event::SubstrateUp { child });
        }
        for child in [Child::Transport(tid(2)), Child::DecryptWorkers, Child::Mdns] {
            s.step(Event::SubstrateFailed { child });
        }
        assert_eq!(s.state(), &SupState::Running);

        // Only the children that came up are torn down; the failed ones never
        // joined the up-set.
        let stops = s.step(Event::Stop);
        assert_eq!(
            stops,
            vec![
                Action::StopChild(Child::Dns),
                Action::StopChild(Child::Nostr),
                Action::StopChild(Child::Transport(tid(1))),
                Action::StopChild(Child::Tun),
            ]
        );
        for a in stops {
            let child = match a {
                Action::StopChild(c) => c,
                _ => panic!("unexpected action"),
            };
            assert_eq!(s.step(Event::ChildStopped { child }), vec![]);
        }
        assert_eq!(s.state(), &SupState::Stopped);
    }

    #[test]
    fn late_substrate_up_in_running_is_inert() {
        let mut s = SupervisorFsm::new();
        s.step(Event::Start {
            transports: vec![tid(1)],
            encrypt_workers: false,
            decrypt_workers: false,
            nostr: false,
            mdns: false,
            tun: false,
            dns: false,
        });
        s.step(Event::SubstrateUp {
            child: Child::Transport(tid(1)),
        });
        assert_eq!(s.state(), &SupState::Running);
        // A stray event in Running produces nothing and does not change state.
        assert_eq!(
            s.step(Event::SubstrateUp {
                child: Child::Nostr
            }),
            vec![]
        );
        assert_eq!(s.state(), &SupState::Running);
    }

    #[test]
    fn drain_from_running_emits_entry_actions_and_enters_draining() {
        let mut s = SupervisorFsm::running_with([
            Child::Dns,
            Child::Nostr,
            Child::Transport(tid(1)),
            Child::Tun,
        ]);
        let actions = s.step(Event::Drain { deadline_ms: 5_000 });
        // Order matters: broadcast → arm timer → gate reconciler off.
        assert_eq!(
            actions,
            vec![
                Action::BroadcastDisconnect,
                Action::SetTimer(Timer::DrainDeadline, 5_000),
                Action::SetPeeringDesired(PeeringDesired::Empty),
                Action::SuspendReplenish,
            ]
        );
        assert_eq!(s.state(), &SupState::Draining { deadline_ms: 5_000 });
    }

    #[test]
    fn drain_deadline_elapsed_yields_teardown_and_enters_stopping() {
        let mut s = SupervisorFsm::running_with([
            Child::Dns,
            Child::Nostr,
            Child::Mdns,
            Child::Transport(tid(2)),
            Child::Transport(tid(1)),
            Child::Tun,
        ]);
        s.step(Event::Drain { deadline_ms: 2_000 });
        let stops = s.step(Event::DrainDeadlineElapsed);
        // Same ordering the immediate `Stop` path authors: dns → nostr → mdns →
        // transports (ascending id) → tun.
        assert_eq!(
            stops,
            vec![
                Action::StopChild(Child::Dns),
                Action::StopChild(Child::Nostr),
                Action::StopChild(Child::Mdns),
                Action::StopChild(Child::Transport(tid(1))),
                Action::StopChild(Child::Transport(tid(2))),
                Action::StopChild(Child::Tun),
            ]
        );
        assert!(matches!(s.state(), SupState::Stopping { .. }));
    }

    #[test]
    fn drain_teardown_matches_immediate_stop_teardown() {
        // The drain path and the immediate-stop path must produce the identical
        // StopChild plan over the same up-set (single teardown author).
        let up = [
            Child::Dns,
            Child::Nostr,
            Child::Mdns,
            Child::Transport(tid(1)),
            Child::Transport(tid(3)),
            Child::Tun,
        ];
        let mut immediate = SupervisorFsm::running_with(up);
        let stop_plan = immediate.step(Event::Stop);

        let mut drained = SupervisorFsm::running_with(up);
        drained.step(Event::Drain { deadline_ms: 1_000 });
        let drain_plan = drained.step(Event::DrainDeadlineElapsed);

        assert_eq!(stop_plan, drain_plan);
    }

    #[test]
    fn drain_is_inert_from_non_running() {
        // From `Created`.
        let mut s = SupervisorFsm::new();
        assert_eq!(s.step(Event::Drain { deadline_ms: 1_000 }), vec![]);
        assert_eq!(s.state(), &SupState::Created);

        // From `Stopping` (seed a drain, close its window, then try to drain
        // again — inert).
        let mut s2 = SupervisorFsm::running_with([Child::Transport(tid(1))]);
        s2.step(Event::Drain { deadline_ms: 1_000 });
        s2.step(Event::DrainDeadlineElapsed);
        assert!(matches!(s2.state(), SupState::Stopping { .. }));
        assert_eq!(s2.step(Event::Drain { deadline_ms: 1_000 }), vec![]);
        assert!(matches!(s2.state(), SupState::Stopping { .. }));
    }

    #[test]
    fn drain_deadline_elapsed_is_inert_outside_draining() {
        // Inert from `Running` (no drain in progress).
        let mut s = SupervisorFsm::running_with([Child::Transport(tid(1))]);
        assert_eq!(s.step(Event::DrainDeadlineElapsed), vec![]);
        assert_eq!(s.state(), &SupState::Running);
    }
}
