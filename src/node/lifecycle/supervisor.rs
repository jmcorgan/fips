//! Node lifecycle supervisor — sans-IO core.
//!
//! A synchronous `step(event) -> Vec<Action>` finite-state machine over the
//! fixed set of substrate children. It owns the *decision* of what to bring up
//! and tear down and in what order; the async driver in [`super`]
//! (`start()`/`stop()`) performs the actual I/O each [`Action`] names and reports
//! results back as [`Event`]s. The core reads no clock, performs no I/O, and
//! holds no runtime handles — time enters only as inputs (a future `Tick`/
//! `DrainDeadlineElapsed`, added with the `Draining` phase) — so it is
//! unit-testable with synthetic sequences and survives a later thread-boundary
//! move (cores are sans-IO).
//!
//! ## Scope: the behavior-neutral rewrite
//!
//! This module is strictly
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
//! `self.state` transitions this module uses. The existing immediate `Stop`
//! path is untouched. `Draining` and `Stop` share a single teardown-plan author
//! (`begin_stopping`), so the teardown ordering is defined once.
//!
//! ## Scope: the `Running{Full|Degraded}` + `Failed` health split (this commit)
//!
//! This module implements the operator-visible start-completion health policy
//! and, with it, the FSM-owned [`Action::PublishState`]:
//!
//! - [`SupState::Running`] now carries a [`Health`] (`Full` or `Degraded`), and
//!   [`SupState::Failed`] is the fatal path. When `Starting.pending` empties (or
//!   the degenerate no-children path), the machine resolves health once
//!   ([`SupervisorFsm::resolve_start_health`]): **zero transports up → `Failed`**
//!   (fatal); **≥1 transport up but a configured optional child failed →
//!   `Degraded`**; **everything configured came up → `Full`**. Not-configured
//!   children never count (a node never asked to run DNS is not degraded for
//!   lacking it); worker-pool failures are `Degraded` at most, never `Failed`.
//! - the health outcome is a fork that a single direct `self.state` write cannot
//!   express, so the machine emits [`Action::PublishState`] carrying the resolved
//!   [`NodeState`]; the driver writes it. The non-forking transitions
//!   (`Starting`/`Draining`/`Stopping`/`Stopped`) keep their direct `self.state`
//!   writes — only the start-completion health outcome routes through
//!   `PublishState`, to minimize churn.
//! - the degenerate no-children path now resolves to `Failed` (zero transports),
//!   **not** the old immediate-`Running`.
//!
//! Runtime child-liveness monitoring (a `ChildExited` event re-routing health
//! when a task/thread dies at runtime) is **deferred**: start-completion health
//! resolution is start-framed, and liveness monitoring is a substantial unbuilt
//! mechanism. This commit is start-time health only.

use std::collections::HashSet;
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::node::NodeState;
use crate::transport::{PacketTx, TransportId};
use crate::upper::tun::{TunOutboundRx, TunTx};

/// A supervised substrate child.
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
/// `Tick` is **deferred** (the per-tick reconciler backstop lands
/// with the cadence work). `ChildExited` is present: it feeds runtime
/// child-liveness monitoring, routing health the same way a start failure does.
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
    /// A supervised child's task or thread exited on its own at runtime — not
    /// in response to a `StopChild`. Valid from `Running`; routes
    /// health the same way a start failure does (the last transport out →
    /// `Failed`, an optional child out → `Degraded`), but at runtime `Failed` is
    /// a published health signal, not a teardown — the driver keeps serving. No
    /// restart (the FSM has no restart action). Inert outside `Running`.
    ChildExited {
        /// The child whose task/thread exited.
        child: Child,
    },
}

/// A driver-scheduled timer the supervisor can arm. Only the
/// drain deadline exists for now; the handshake/rekey/liveness timers
/// arrive with later cores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Timer {
    /// Fires when the bounded drain window closes. The driver feeds
    /// [`Event::DrainDeadlineElapsed`] when it elapses (or earlier, when all
    /// peers have drained).
    DrainDeadline,
}

/// The reconciler's desired peering set (drain gate). Only
/// `Empty` is needed for now; the populated variants that the
/// homeostatic reconciler converges toward land with that core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PeeringDesired {
    /// No peers desired. Entering `Draining` sets this so the reconciler stops
    /// reconnecting the peers the drain just closed ("Draining switches the
    /// homeostat off").
    Empty,
}

/// An effect the driver must perform. The core never performs I/O itself.
///
/// `PublishState` lands here, with the `Running{Full|Degraded}`
/// health split: the start-completion health outcome is a fork
/// (`Full`/`Degraded`/`Failed`) that a single direct `self.state` write cannot
/// express, so the machine authors it as an action. The driver keeps its direct
/// `self.state` writes for the non-forking transitions (`Starting`/`Draining`/
/// `Stopping`/`Stopped`); only the start-completion health outcome routes through
/// `PublishState`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Bring up this child (the driver performs the spawn / start I/O and
    /// reports `SubstrateUp` or `SubstrateFailed`).
    SpawnChild(Child),
    /// Publish the given operator-visible [`NodeState`]. Emitted at start
    /// completion (when `Starting.pending` empties, or the degenerate
    /// no-children path) to carry the resolved health outcome —
    /// [`NodeState::Running`] (Full), [`NodeState::Degraded`], or
    /// [`NodeState::Failed`] — to the driver, which writes it to the published
    /// state.
    PublishState(NodeState),
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
    /// Set the reconciler's desired peering set (drain gate). Documented
    /// **no-op for now** — the reconciler that consumes it is not yet
    /// built; the driver logs/ignores it for now.
    SetPeeringDesired(PeeringDesired),
    /// Suspend peer replenishment (drain gate). Documented **no-op for
    /// now** for the same reason as `SetPeeringDesired`.
    SuspendReplenish,
}

/// Start-completion health. Resolved once when
/// `Starting.pending` empties: `Full` iff every configured child came up,
/// `Degraded` iff ≥1 transport is up but some configured optional child failed.
/// Zero transports up is not a health — it is the fatal [`SupState::Failed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Health {
    /// Every configured child came up.
    Full,
    /// ≥1 transport is up, but one or more configured optional children failed
    /// to start (a transport beyond the first, Nostr, mDNS, TUN, DNS, or a
    /// worker-pool spawn). The node is operational (serving) but degraded.
    Degraded {
        /// The configured children that failed to start.
        reasons: HashSet<Child>,
    },
}

/// Reason for the fatal [`SupState::Failed`] state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailReason {
    /// Zero transports came up at start completion. Without a transport the node
    /// cannot serve, so this is fatal (the driver tears down and returns an
    /// error), unlike the degraded-but-serving optional-child failures.
    NoTransports,
}

/// Internal supervisor state. Richer than the published
/// [`NodeState`](crate::node::NodeState): `Starting`/`Stopping` carry the set of
/// children still resolving, and `Running` carries the resolved [`Health`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SupState {
    /// Constructed but not started.
    Created,
    /// Bringing children up; `pending` is the set not yet resolved.
    Starting {
        /// Children asked to spawn that have not yet reported up-or-failed.
        pending: HashSet<Child>,
    },
    /// All children resolved and ≥1 transport up; node operational. Carries the
    /// resolved [`Health`] (`Full` or `Degraded`).
    Running {
        /// Resolved start-completion health.
        health: Health,
    },
    /// Start completed with zero transports up — fatal. The
    /// driver tears down any children that did come up and returns an error.
    Failed {
        /// Why the start failed.
        reason: FailReason,
    },
    /// Bounded graceful-drain window. Broadcast Disconnect
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
    /// Configured children that failed to start during the current bring-up.
    /// Feeds the `Degraded` health determination when `pending` empties.
    failed: HashSet<Child>,
}

impl SupervisorFsm {
    /// A fresh supervisor in `Created`.
    pub(crate) fn new() -> Self {
        Self {
            state: SupState::Created,
            up: HashSet::new(),
            failed: HashSet::new(),
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
            state: SupState::Running {
                health: Health::Full,
            },
            up: up.into_iter().collect(),
            failed: HashSet::new(),
        }
    }

    /// Current internal state (for the driver's bookkeeping and for tests).
    #[cfg(test)]
    pub(crate) fn state(&self) -> &SupState {
        &self.state
    }

    /// The configured children that failed to start during bring-up. The driver
    /// reads this on the `Degraded` start outcome to enumerate the degraded
    /// children in an operator-visible `warn!`.
    pub(in crate::node) fn failed(&self) -> &HashSet<Child> {
        &self.failed
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
            Event::ChildExited { child } => self.on_child_exited(child),
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
        self.failed.clear();

        // A node with no children at all resolves health immediately. Zero
        // transports up → `Failed` (this is the behavioral
        // change from the old immediate-`Running`).
        if order.is_empty() {
            return vec![Action::PublishState(self.resolve_start_health())];
        }

        self.state = SupState::Starting {
            pending: order.iter().copied().collect(),
        };
        order.into_iter().map(Action::SpawnChild).collect()
    }

    fn on_substrate_up(&mut self, child: Child) -> Vec<Action> {
        let SupState::Starting { pending } = &mut self.state else {
            return Vec::new();
        };
        pending.remove(&child);
        let emptied = pending.is_empty();
        self.up.insert(child);
        if emptied {
            vec![Action::PublishState(self.resolve_start_health())]
        } else {
            Vec::new()
        }
    }

    fn on_substrate_failed(&mut self, child: Child) -> Vec<Action> {
        // Record the failed child: a configured child that
        // failed to start drives the `Degraded` determination when `pending`
        // empties. It drains from `pending` and never joins the up-set.
        let SupState::Starting { pending } = &mut self.state else {
            return Vec::new();
        };
        pending.remove(&child);
        let emptied = pending.is_empty();
        self.failed.insert(child);
        if emptied {
            vec![Action::PublishState(self.resolve_start_health())]
        } else {
            Vec::new()
        }
    }

    /// Resolve start-completion health. Called once when
    /// `Starting.pending` empties (or the degenerate no-children path); the
    /// classification is shared with runtime child-exit via
    /// [`Self::classify_health`].
    fn resolve_start_health(&mut self) -> NodeState {
        self.classify_health()
    }

    /// Classify health from the current `up` / `failed` sets and set the
    /// resulting state, returning the [`NodeState`] the driver should publish.
    /// Shared by start-completion ([`Self::resolve_start_health`]) and runtime
    /// child-exit ([`Self::on_child_exited`]):
    ///
    /// - zero transports up → [`SupState::Failed`] / [`NodeState::Failed`];
    /// - ≥1 transport up but some child in `failed` → [`Health::Degraded`] /
    ///   [`NodeState::Degraded`];
    /// - everything up and nothing failed → [`Health::Full`] / [`NodeState::Running`].
    ///
    /// Worker-pool failures are captured in `failed` like any other optional
    /// child, so they contribute `Degraded` (never `Failed`) — the inline crypto
    /// fallback keeps the node correct without the pools.
    fn classify_health(&mut self) -> NodeState {
        let transports_up = self
            .up
            .iter()
            .filter(|c| matches!(c, Child::Transport(_)))
            .count();
        if transports_up == 0 {
            self.state = SupState::Failed {
                reason: FailReason::NoTransports,
            };
            NodeState::Failed
        } else if !self.failed.is_empty() {
            self.state = SupState::Running {
                health: Health::Degraded {
                    reasons: self.failed.clone(),
                },
            };
            NodeState::Degraded
        } else {
            self.state = SupState::Running {
                health: Health::Full,
            };
            NodeState::Running
        }
    }

    fn on_stop(&mut self) -> Vec<Action> {
        if !matches!(self.state, SupState::Running { .. }) {
            return Vec::new();
        }
        self.begin_stopping()
    }

    fn on_drain(&mut self, deadline_ms: u64) -> Vec<Action> {
        // Only a graceful drain from a running node (either health). Inert
        // otherwise (matching `Stop`'s guard).
        if !matches!(self.state, SupState::Running { .. }) {
            return Vec::new();
        }
        self.state = SupState::Draining { deadline_ms };
        // Drain entry, in order: broadcast the shutdown Disconnect, arm the
        // deadline timer, then gate the reconciler off (desired = ∅, suspend
        // replenishment) so it cannot reconnect the peers the drain just
        // closed. The up-set is left intact for the eventual teardown plan.
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

    /// A supervised child exited on its own at runtime. Only
    /// meaningful while `Running`: startup (`Starting`), drain (`Draining`), and
    /// teardown (`Stopping`) own their own child bookkeeping through the
    /// `pending` / `up` sets and the `SubstrateUp` / `SubstrateFailed` /
    /// `ChildStopped` events, so a stray exit signal in those states is ignored.
    ///
    /// The exit is routed exactly like a start-time failure via
    /// [`Self::classify_health`] — the last transport out → `Failed`, an optional
    /// child out → `Degraded{+child}` — the runtime analogue of the
    /// start-time policy. Two differences from start: `Failed` here is a
    /// published health signal only (the driver keeps serving, per the resolved
    /// runtime policy — no auto-teardown), and there is no restart (the FSM has
    /// no restart action). If the exiting child is not currently up (a duplicate
    /// signal, or one that never came up) the machine is unchanged and emits
    /// nothing.
    fn on_child_exited(&mut self, child: Child) -> Vec<Action> {
        if !matches!(self.state, SupState::Running { .. }) {
            return Vec::new();
        }
        if !self.up.remove(&child) {
            return Vec::new();
        }
        self.failed.insert(child);
        vec![Action::PublishState(self.classify_health())]
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
    fn all_configured_up_reaches_full() {
        // Everything configured came up (2 transports + all optional children)
        // → Full; the pending-emptying step publishes `Running`.
        let mut s = SupervisorFsm::new();
        let spawns = s.step(start_full());
        let children: Vec<Child> = spawns
            .into_iter()
            .map(|a| match a {
                Action::SpawnChild(c) => c,
                _ => panic!("unexpected action"),
            })
            .collect();
        let last = children.len() - 1;
        for (i, child) in children.into_iter().enumerate() {
            let out = s.step(Event::SubstrateUp { child });
            if i == last {
                assert_eq!(out, vec![Action::PublishState(NodeState::Running)]);
            } else {
                assert_eq!(out, vec![]);
            }
        }
        assert_eq!(
            s.state(),
            &SupState::Running {
                health: Health::Full
            }
        );
        assert!(s.failed().is_empty());
    }

    #[test]
    fn configured_optional_child_failure_is_degraded() {
        // A configured optional child (mDNS) fails but ≥1 transport is up →
        // Degraded, with the failed child in `reasons`. The node stays
        // operational and tears down cleanly (the failed child never joined the
        // up-set, so it is excluded from teardown; workers excluded by design).
        let mut s = SupervisorFsm::new();
        s.step(start_full());
        for child in [
            Child::Transport(tid(1)),
            Child::Transport(tid(2)),
            Child::EncryptWorkers,
            Child::DecryptWorkers,
            Child::Nostr,
        ] {
            assert_eq!(s.step(Event::SubstrateUp { child }), vec![]);
        }
        // mdns fails, tun comes up, dns comes up last (empties pending).
        assert_eq!(
            s.step(Event::SubstrateFailed { child: Child::Mdns }),
            vec![]
        );
        assert_eq!(s.step(Event::SubstrateUp { child: Child::Tun }), vec![]);
        assert_eq!(
            s.step(Event::SubstrateUp { child: Child::Dns }),
            vec![Action::PublishState(NodeState::Degraded)]
        );
        let mut expected_reasons = HashSet::new();
        expected_reasons.insert(Child::Mdns);
        assert_eq!(
            s.state(),
            &SupState::Running {
                health: Health::Degraded {
                    reasons: expected_reasons.clone()
                }
            }
        );
        assert_eq!(s.failed(), &expected_reasons);

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
    fn worker_pool_failure_is_degraded_not_failed() {
        // A worker-pool spawn failure is Degraded at most, never Failed
        // (inline crypto fallback keeps the node correct). One transport is up.
        let mut s = SupervisorFsm::new();
        s.step(Event::Start {
            transports: vec![tid(1)],
            encrypt_workers: true,
            decrypt_workers: false,
            nostr: false,
            mdns: false,
            tun: false,
            dns: false,
        });
        assert_eq!(
            s.step(Event::SubstrateUp {
                child: Child::Transport(tid(1))
            }),
            vec![]
        );
        assert_eq!(
            s.step(Event::SubstrateFailed {
                child: Child::EncryptWorkers
            }),
            vec![Action::PublishState(NodeState::Degraded)]
        );
        let mut expected = HashSet::new();
        expected.insert(Child::EncryptWorkers);
        assert_eq!(
            s.state(),
            &SupState::Running {
                health: Health::Degraded { reasons: expected }
            }
        );
    }

    #[test]
    fn not_configured_child_does_not_cause_degraded() {
        // A node that never asked to run mDNS/TUN/DNS/Nostr is not degraded for
        // lacking them: only a configured-and-failed child counts. One transport
        // configured and up, nothing else configured → Full.
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
        assert_eq!(
            s.step(Event::SubstrateUp {
                child: Child::Transport(tid(1))
            }),
            vec![Action::PublishState(NodeState::Running)]
        );
        assert_eq!(
            s.state(),
            &SupState::Running {
                health: Health::Full
            }
        );
    }

    #[test]
    fn zero_transports_up_is_failed_via_child_failures() {
        // Transports were configured but all failed → zero transports up →
        // Failed (fatal), even though other children came up. Failed takes
        // priority over Degraded.
        let mut s = SupervisorFsm::new();
        s.step(Event::Start {
            transports: vec![tid(1)],
            encrypt_workers: false,
            decrypt_workers: false,
            nostr: true,
            mdns: false,
            tun: false,
            dns: false,
        });
        assert_eq!(
            s.step(Event::SubstrateFailed {
                child: Child::Transport(tid(1))
            }),
            vec![]
        );
        assert_eq!(
            s.step(Event::SubstrateUp {
                child: Child::Nostr
            }),
            vec![Action::PublishState(NodeState::Failed)]
        );
        assert_eq!(
            s.state(),
            &SupState::Failed {
                reason: FailReason::NoTransports
            }
        );
    }

    #[test]
    fn no_children_is_failed_immediately() {
        // The degenerate empty-`Start` path: zero transports → Failed (the
        // behavioral change from the old immediate-Running).
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
        assert_eq!(actions, vec![Action::PublishState(NodeState::Failed)]);
        assert_eq!(
            s.state(),
            &SupState::Failed {
                reason: FailReason::NoTransports
            }
        );
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
        // Every spawned child reports an outcome: five come up, three fail.
        // `pending` drains fully; one transport (tid(1)) is up so the node
        // reaches `Running`, but a configured transport (tid(2)) and two
        // configured optional children failed → Degraded.
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
        assert!(matches!(
            s.state(),
            SupState::Running {
                health: Health::Degraded { .. }
            }
        ));

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
        assert_eq!(
            s.state(),
            &SupState::Running {
                health: Health::Full
            }
        );
        // A stray event in Running produces nothing and does not change state.
        assert_eq!(
            s.step(Event::SubstrateUp {
                child: Child::Nostr
            }),
            vec![]
        );
        assert_eq!(
            s.state(),
            &SupState::Running {
                health: Health::Full
            }
        );
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
        assert_eq!(
            s.state(),
            &SupState::Running {
                health: Health::Full
            }
        );
    }

    #[test]
    fn child_exited_optional_is_degraded() {
        // An optional child (Nostr) exits at runtime with a transport still up →
        // Degraded, the exited child recorded in `reasons` and dropped from `up`.
        let mut s = SupervisorFsm::running_with([
            Child::Transport(tid(1)),
            Child::Nostr,
            Child::Tun,
            Child::Dns,
        ]);
        assert_eq!(
            s.step(Event::ChildExited {
                child: Child::Nostr
            }),
            vec![Action::PublishState(NodeState::Degraded)]
        );
        let mut reasons = HashSet::new();
        reasons.insert(Child::Nostr);
        assert_eq!(
            s.state(),
            &SupState::Running {
                health: Health::Degraded {
                    reasons: reasons.clone()
                }
            }
        );
        assert_eq!(s.failed(), &reasons);
    }

    #[test]
    fn child_exited_transport_beyond_first_is_degraded() {
        // One of several transports exits → Degraded (≥1 transport remains up),
        // not Failed.
        let mut s =
            SupervisorFsm::running_with([Child::Transport(tid(1)), Child::Transport(tid(2))]);
        assert_eq!(
            s.step(Event::ChildExited {
                child: Child::Transport(tid(1))
            }),
            vec![Action::PublishState(NodeState::Degraded)]
        );
        assert!(matches!(
            s.state(),
            SupState::Running {
                health: Health::Degraded { .. }
            }
        ));
    }

    #[test]
    fn child_exited_last_transport_is_failed() {
        // The only transport exits → Failed (published), but no teardown action:
        // per the runtime policy the driver keeps serving on the Failed health
        // signal; the FSM emits only `PublishState(Failed)`.
        let mut s = SupervisorFsm::running_with([Child::Transport(tid(1)), Child::Dns]);
        assert_eq!(
            s.step(Event::ChildExited {
                child: Child::Transport(tid(1))
            }),
            vec![Action::PublishState(NodeState::Failed)]
        );
        assert_eq!(
            s.state(),
            &SupState::Failed {
                reason: FailReason::NoTransports
            }
        );
    }

    #[test]
    fn child_exited_accumulates_reasons_then_fails_on_last_transport() {
        // Runtime exits accumulate in `reasons` and stay Degraded while a
        // transport survives; the last transport out flips to Failed.
        let mut s = SupervisorFsm::running_with([
            Child::Transport(tid(1)),
            Child::Transport(tid(2)),
            Child::Nostr,
        ]);
        assert_eq!(
            s.step(Event::ChildExited {
                child: Child::Nostr
            }),
            vec![Action::PublishState(NodeState::Degraded)]
        );
        assert_eq!(
            s.step(Event::ChildExited {
                child: Child::Transport(tid(1))
            }),
            vec![Action::PublishState(NodeState::Degraded)]
        );
        // Still Degraded (tid(2) up); reasons carry both prior exits.
        let mut reasons = HashSet::new();
        reasons.insert(Child::Nostr);
        reasons.insert(Child::Transport(tid(1)));
        assert_eq!(s.failed(), &reasons);
        // Last transport out → Failed.
        assert_eq!(
            s.step(Event::ChildExited {
                child: Child::Transport(tid(2))
            }),
            vec![Action::PublishState(NodeState::Failed)]
        );
        assert!(matches!(s.state(), SupState::Failed { .. }));
    }

    #[test]
    fn child_exited_is_inert_outside_running() {
        // From `Created`: no producer should fire pre-Running, but a stray signal
        // is ignored.
        let mut created = SupervisorFsm::new();
        assert_eq!(
            created.step(Event::ChildExited {
                child: Child::Nostr
            }),
            vec![]
        );
        assert_eq!(created.state(), &SupState::Created);

        // From `Draining`: a child exiting during the drain window is the drain's
        // own teardown, owned by the `ChildStopped` path — ignore it here.
        let mut draining = SupervisorFsm::running_with([Child::Transport(tid(1)), Child::Dns]);
        draining.step(Event::Drain { deadline_ms: 1_000 });
        assert_eq!(
            draining.step(Event::ChildExited { child: Child::Dns }),
            vec![]
        );
        assert!(matches!(draining.state(), SupState::Draining { .. }));
    }

    #[test]
    fn child_exited_unknown_child_is_noop() {
        // A child not in the up-set (duplicate signal, or never up) leaves the
        // machine unchanged and emits nothing.
        let mut s = SupervisorFsm::running_with([Child::Transport(tid(1))]);
        assert_eq!(
            s.step(Event::ChildExited {
                child: Child::Nostr
            }),
            vec![]
        );
        assert_eq!(
            s.state(),
            &SupState::Running {
                health: Health::Full
            }
        );
        assert!(s.failed().is_empty());
    }
}
