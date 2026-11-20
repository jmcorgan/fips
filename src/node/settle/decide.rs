//! The settlement core beside the node, in test builds only.
//!
//! [`Shadow`] holds a copy of the core's [`Table`] that each of the node's
//! decision sites feeds the input it would build, after its own decision,
//! and that decides nothing: its outputs change no state of the node. It is
//! the run that shows, test by test, where the core and the node part.
//!
//! The core numbers its own links, so the shadow keeps the node's link id
//! for each number it hands out: a dial's [`Output::Opened`] and an admitted
//! msg1's [`Output::Ask`] name the link the site was on. Its legs hold
//! leases the node's own index allocator never drew
//! ([`IndexLease::for_test`] of the index the node drew); each lease the
//! shadow hands back is released, the lease of each peer it installs is kept
//! until that peer goes, and a dropped node closes the shadow and releases
//! whatever its legs and peers still hold. [`Leases`] counts both ends, since
//! in a root test build the core's own count of dropped leases is
//! process-wide.

use portable_atomic::AtomicU64;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::NodeAddr;
use crate::node::Node;
use crate::node::settle::exec::Did;
use crate::peer::{ActivePeer, PeerInstant, peer_now};
use crate::proto::rekey::IndexLease;
use crate::proto::settle::input::Input;
use crate::proto::settle::legs::Start;
use crate::proto::settle::links::{Dir, Holder, LinkNo, Pair};
use crate::proto::settle::output::{Output, Why};
use crate::proto::settle::table::{Held, Table};
use crate::transport::{LinkDirection, LinkId, TransportAddr, TransportId};

/// The leases a shadow minted and released, shared with whoever asked, so
/// they can be read after its node is dropped.
#[derive(Debug, Default)]
pub(in crate::node) struct Leases {
    minted: AtomicU64,
    freed: AtomicU64,
}

impl Leases {
    /// How many leases the shadow minted.
    pub(in crate::node) fn minted(&self) -> u64 {
        self.minted.load(Ordering::Relaxed)
    }

    /// How many of them it released.
    pub(in crate::node) fn freed(&self) -> u64 {
        self.freed.load(Ordering::Relaxed)
    }
}

/// The settlement core beside one node.
#[derive(Default)]
pub(in crate::node) struct Shadow {
    /// The table, built at the first input from the node's address and
    /// configuration then, since a test may change either after it builds
    /// the node.
    table: Option<Table<PeerInstant>>,
    /// The core's number for each of the node's links it was told of.
    nos: HashMap<LinkId, LinkNo>,
    /// The lease of each peer the shadow installed.
    sessions: HashMap<NodeAddr, IndexLease>,
    /// The leases minted and released.
    leases: Arc<Leases>,
    /// How many inputs of each kind the shadow took, and how many polls,
    /// by the name of the input.
    seen: Mutex<BTreeMap<&'static str, u64>>,
    /// What the node did, and what the core decided, since the live audit
    /// last compared them.
    logs: Mutex<Logs>,
    /// The comparison found a first difference, after which the shadow's
    /// state is no longer the node's and nothing more is compared.
    diverged: AtomicBool,
    /// The node's address, read when the table was built.
    me: Option<NodeAddr>,
    /// The node's links whose records the shadow retired, by its own timers
    /// or at an input, while the node still holds the links: the node
    /// closes them later in the same entry, or the comparison is to show
    /// that it does not, so a resync meanwhile must not take such a link,
    /// its machine or its peer for one a test planted.
    reaped: std::collections::HashSet<LinkId>,
    /// The node's links a decision site named as the link its input opens:
    /// what the core makes of such a link is the comparison's to read, so a
    /// resync never takes one for a link a test opened past the sites.
    fed: std::collections::HashSet<LinkId>,
    /// The instant, on the interval clock's milliseconds, the node's timers
    /// are running at, while they run: a test may drive them at an instant
    /// of its own rather than the clock's, and the shadow then decides at
    /// the same one.
    clock: Option<u64>,
    /// The first difference the comparison found that `shadow.txt` does
    /// not list, which fails the test when the node is dropped.
    unlisted: Mutex<Option<String>>,
    /// The node's links a test planted a dial's leg on past the dial site
    /// that the shadow has not taken yet: it takes each once, at the first
    /// resync that numbers the link, on a link a peer holds as on any
    /// other.
    planted: std::collections::HashSet<LinkId>,
    /// The connections the node closed, and the core decided to close,
    /// since the live audit last compared them.
    closes: Mutex<Closes>,
}

/// The connections the node closed, and the connections the shadow core
/// decided to close, since the last comparison.
#[derive(Debug, Default)]
pub(in crate::node) struct Closes {
    /// Each pair the node closed, at the close sites of its decisions.
    pub(in crate::node) node: Vec<Pair>,
    /// Each pair of the core's `Retire`, `Release` and `Close` outputs.
    pub(in crate::node) core: Vec<Pair>,
}

/// The node's and the core's words since the last comparison.
#[derive(Debug, Default)]
pub(in crate::node) struct Logs {
    /// What the node did.
    pub(in crate::node) node: Vec<Did>,
    /// What the core decided.
    pub(in crate::node) core: Vec<Did>,
}

impl Shadow {
    /// The core's number for the node's link `id`, if the shadow was told
    /// of it.
    pub(in crate::node) fn no(&self, id: LinkId) -> Option<LinkNo> {
        self.nos.get(&id).copied()
    }

    /// The node's link the core numbers `no`.
    pub(in crate::node) fn id(&self, no: LinkNo) -> Option<LinkId> {
        self.nos
            .iter()
            .find_map(|(id, n)| (*n == no).then_some(*id))
    }

    /// Each of the node's links the shadow numbers, with its number.
    pub(in crate::node) fn numbered(&self) -> impl Iterator<Item = (&LinkId, &LinkNo)> {
        self.nos.iter()
    }

    /// How many inputs named `kind` the shadow took (`tick` for a poll).
    pub(in crate::node) fn seen(&self, kind: &str) -> u64 {
        let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.get(kind).copied().unwrap_or(0)
    }

    /// Take what the node did and the core decided since the last call.
    pub(in crate::node) fn take(&self) -> Logs {
        std::mem::take(&mut *self.logs.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Take the connections the node closed and the core decided to close
    /// since the last call.
    pub(in crate::node) fn closes(&self) -> Closes {
        std::mem::take(&mut *self.closes.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Whether the comparison has found its first difference.
    pub(in crate::node) fn diverged(&self) -> bool {
        self.diverged.load(Ordering::Relaxed)
    }

    /// Mark the first difference found: nothing more is compared.
    pub(in crate::node) fn diverge(&self) {
        self.diverged.store(true, Ordering::Relaxed);
    }

    /// Keep `message`, a first difference `shadow.txt` does not list, to
    /// fail the test with when the node is dropped.
    pub(in crate::node) fn fail(&self, message: String) {
        let mut unlisted = self.unlisted.lock().unwrap_or_else(|e| e.into_inner());
        unlisted.get_or_insert(message);
    }

    /// The instant the shadow decides at, and is compared at: the one the
    /// node's timers run at while they run, and the peer clock's now
    /// otherwise.
    pub(in crate::node) fn now(&self) -> PeerInstant {
        match self.clock {
            Some(ms) => crate::time::at::<crate::time::HostClock>(ms),
            None => peer_now(),
        }
    }

    /// The table, if any input has built it.
    pub(in crate::node) fn table(&self) -> Option<&Table<PeerInstant>> {
        self.table.as_ref()
    }

    /// A lease on `index` for an input, counted as minted.
    pub(in crate::node) fn lease(&self, index: u32) -> IndexLease {
        self.leases.minted.fetch_add(1, Ordering::Relaxed);
        IndexLease::for_test(index)
    }

    /// The shadow's lease counts, to read after its node is dropped.
    pub(in crate::node) fn leases(&self) -> Arc<Leases> {
        Arc::clone(&self.leases)
    }

    /// Record what the core decided in `out`, one step's outputs.
    fn decided(&self, out: &[Output]) {
        self.closing(out);
        let did = super::exec::from_core(out);
        if !did.is_empty() {
            let mut logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
            logs.core.extend(did);
        }
    }

    /// Record the connections the core decided to close in `out`, one
    /// step's outputs: the pairs of each `Retire`, `Release` and `Close`.
    fn closing(&self, out: &[Output]) {
        let pairs = out.iter().flat_map(|o| match o {
            Output::Retire { closes, .. }
            | Output::Release { closes, .. }
            | Output::Close { closes } => closes.as_slice(),
            _ => &[],
        });
        let mut closes = self.closes.lock().unwrap_or_else(|e| e.into_inner());
        closes.core.extend(pairs.cloned());
    }

    /// Count one input named `kind`.
    fn count(&self, kind: &'static str) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        *seen.entry(kind).or_insert(0) += 1;
    }

    /// Release `lease`, counting it.
    fn free(&self, lease: IndexLease) {
        let _ = lease.release();
        self.leases.freed.fetch_add(1, Ordering::Relaxed);
    }

    /// Carry out what the shadow's own leases and numbers need of `out`,
    /// the outputs of one step, naming any link it opened or asked about
    /// `at`: each lease handed back is released, an installed peer's lease
    /// kept in place of any it held, a removed peer's released, and a
    /// retired link's number forgotten. Nothing else of an output is run.
    fn settle(&mut self, at: Option<LinkId>, out: Vec<Output>) {
        for o in out {
            match o {
                Output::Opened { link } | Output::Ask { link, .. } => {
                    if let Some(id) = at {
                        self.nos.insert(id, link);
                    }
                }
                Output::Free { lease } => self.free(lease),
                Output::Install(install) => {
                    if let Some(old) = self.sessions.insert(install.peer, install.lease) {
                        self.free(old);
                    }
                }
                Output::Remove { peer, .. } => {
                    if let Some(old) = self.sessions.remove(&peer) {
                        self.free(old);
                    }
                }
                Output::Retire { link, .. } => {
                    let gone = self.nos.iter().filter(|(_, n)| **n == link);
                    let gone: Vec<LinkId> = gone.map(|(id, _)| *id).collect();
                    self.reaped.extend(gone);
                    self.nos.retain(|_, n| *n != link);
                }
                Output::Answer { .. }
                | Output::Resend { .. }
                | Output::Rekey { .. }
                | Output::Reset { .. }
                | Output::Release { .. }
                | Output::Close { .. }
                | Output::Swapped { .. }
                | Output::Retry { .. }
                | Output::Reject { .. } => {}
            }
        }
    }

    /// Close the table: every leg's lease, every peer's and every link's
    /// number given back.
    fn close(&mut self) {
        if let Some(mut table) = self.table.take() {
            let out = table.close(peer_now());
            self.settle(None, out);
        }
        for (_, lease) in std::mem::take(&mut self.sessions) {
            self.free(lease);
        }
        self.nos.clear();
    }
}

impl Shadow {
    /// Append to the file `FIPS_CORE_SHADOW` names, if any, how many inputs
    /// of each kind the shadow took over its node's life, one row:
    /// `seen <thread> <node> <kind>=<count>...`, so a run of the suite can
    /// count the decision sites it reached.
    fn report(&self) {
        let (Some(me), Ok(seen)) = (self.me, self.seen.lock()) else {
            return;
        };
        if seen.is_empty() {
            return;
        }
        let counts: Vec<String> = seen.iter().map(|(k, n)| format!("{k}={n}")).collect();
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("unnamed");
        line(&format!("seen {name} {me} {}", counts.join(" ")));
    }
}

/// The environment variable naming the file the shadow's lines go to.
pub(in crate::node) const VAR: &str = "FIPS_CORE_SHADOW";

/// The mutation lane's switches the settlement core reads by `node_fault!`
/// (under `core/src/proto/settle/`): turned on, each changes what the
/// shadow core decides, and the node is still the spec it is compared
/// with.
pub(in crate::node) const CORE_READS: &[&str] = &[
    "AnswerBeforeAdmit",
    "AttributeByCurrent",
    "AttributeBySetupOnly",
    "BackoffDoubles",
    "CapNotCounted",
    "CapableIgnored",
    "CloseByPeerAddress",
    "CloseBySetupAddress",
    "ConnectingCloses",
    "ConnectingUnlinked",
    "FirstResendAtInterval",
    "FollowResets",
    "FrameForgetsReplays",
    "HeardMovesPeer",
    "IntervalTen",
    "MemoryNeverDropped",
    "MemoryNeverExpires",
    "MoveClosesNewPair",
    "MoveKeepsReplayMemory",
    "MoveLeavesDialOpen",
    "OriginIgnored",
    "OutboundGated",
    "OrphanedNoRetry",
    "RedialKeptAtDisconnect",
    "RedialNoRetry",
    "RedialSwapHeard",
    "ReleasedSetupIndexed",
    "RemovalClosesEveryPair",
    "RestartNoRetry",
    "SilentReadsHeard",
    "StandbyRoamResets",
    "SwitchLeavesPeer",
    "SwitchWritesLive",
    "TeardownIgnoresKeep",
    "UnpinOwnOnly",
    "UnsendableCloses",
    "UnsendableKeepsRedial",
    "UnsentDueAtWake",
    "UnsentPastCap",
    "UnsentStaysDue",
];

/// The mutation lane's switches the settlement core does not read whose
/// break of the node the shadow's comparison is to fail a test on: a
/// node-side site switch the shadow is shown able to catch.
pub(in crate::node) const SHADOW_REDS: &[&str] = &["CrossedRunsKeep"];

/// Whether a switch of the mutation lane is on that the settlement core
/// does not read ([`CORE_READS`]), other than one the comparison is to
/// fail a test on ([`SHADOW_REDS`]): it breaks the node and not the core,
/// so the node is no longer the spec, and a difference the shadow then
/// finds fails nothing. The test fails, or not, at its own assertions.
pub(in crate::node) fn node_broken() -> bool {
    use fips_core::faults::{Fault, on};
    Fault::ALL
        .iter()
        .any(|f| on(*f) && !CORE_READS.contains(&f.name()) && !SHADOW_REDS.contains(&f.name()))
}

/// Append `text` as one line to the file [`VAR`] names, if it names one.
pub(in crate::node) fn line(text: &str) {
    use std::io::Write;
    use std::sync::OnceLock;
    static FILE: OnceLock<Option<String>> = OnceLock::new();
    let Some(path) = FILE.get_or_init(|| std::env::var(VAR).ok()) else {
        return;
    };
    let written = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| f.write_all(format!("{text}\n").as_bytes()));
    if let Err(e) = written {
        panic!("{VAR}: cannot append to {path}: {e}");
    }
}

impl Drop for Shadow {
    /// A node going away closes its shadow, so every lease the shadow holds
    /// is released; and fails the test with the first difference the
    /// comparison found that `shadow.txt` does not list, unless the test is
    /// already failing. The failure waits for the drop so that a test that
    /// breaks the node fails at its own assertion first.
    fn drop(&mut self) {
        let unlisted = self
            .unlisted
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        // The mutation lane's break: the shadow is dropped holding its
        // legs' and peers' leases.
        if !node_fault!(ShadowKeepsLeases) {
            self.close();
            self.report();
        }
        if let Some(message) = unlisted
            && !std::thread::panicking()
        {
            panic!("{message}");
        }
    }
}

/// A handshake the shadow's resync takes from the node: its link, its
/// lease's index, the identity it dialed or learned, its msg1, the msg2 an
/// answer stored, and the instants it is reaped and next resends at.
type Carried = (
    LinkId,
    u32,
    Option<NodeAddr>,
    Vec<u8>,
    Option<Vec<u8>>,
    PeerInstant,
    Option<PeerInstant>,
);

/// The pair `link` was set up at.
fn setup(link: &crate::transport::Link) -> Pair {
    pair(link.transport_id(), link.remote_addr())
}

/// The direction of `link`, in the core's words.
fn dir(link: &crate::transport::Link) -> Dir {
    match link.direction() {
        LinkDirection::Inbound => Dir::Inbound,
        LinkDirection::Outbound => Dir::Outbound,
    }
}

/// The core's pair for `addr` on `transport`.
fn pair(transport: TransportId, addr: &TransportAddr) -> Pair {
    Pair {
        transport,
        addr: addr.clone(),
    }
}

/// The pair `peer` is at, as its link's transport and current address give
/// it, or an empty address on transport 0 for a peer that has neither.
fn current(peer: &ActivePeer) -> Pair {
    Pair {
        transport: peer.transport_id().unwrap_or_else(|| TransportId::new(0)),
        addr: peer
            .current_addr()
            .cloned()
            .unwrap_or_else(|| TransportAddr::new(Vec::new())),
    }
}

/// The core's record of `peer`, held on the core's link `link`, from the
/// peer's own facts: its epoch, the pair it is at, whether it is heard, the
/// instants of its promotion and of its last frame (the instant it was
/// last heard at, once a frame came or, on a heard peering, once it
/// differs from its promotion), and the ephemeral of the msg1 it was
/// promoted from. An unheard peering has had no frame, and the core reads
/// its floor from its promotion and counts its end as silent, so a test
/// that backdates its promotion alone gives it no last frame.
fn held(peer: &ActivePeer, link: LinkNo) -> Held<PeerInstant> {
    let framed = peer.heard() || (peer.is_heard() && peer.heard_at() != peer.promoted_at());
    Held {
        link,
        epoch: peer.remote_epoch().unwrap_or_default(),
        current: current(peer),
        heard: peer.is_heard(),
        installed: peer.promoted_at(),
        last: framed.then_some(peer.heard_at()),
        setup: peer.setup_ephemeral(),
        sending: None,
    }
}

/// The name a site count goes under for `input`.
fn kind(input: &Input) -> &'static str {
    match input {
        Input::Dial(_) => "Dial",
        Input::Connecting { .. } => "Connecting",
        Input::Punched(_) => "Punched",
        Input::ConnectFailed { .. } => "ConnectFailed",
        Input::Arrived { .. } => "Arrived",
        Input::Msg1 { .. } => "Msg1",
        Input::Replace(_) => "Replace",
        Input::Redial(_) => "Redial",
        Input::LegHeard { .. } => "LegHeard",
        Input::Hello(_) => "Hello",
        Input::Abandon { .. } => "Abandon",
        Input::Msg2 { .. } => "Msg2",
        Input::Restarted { .. } => "Restarted",
        Input::Ended { .. } => "Ended",
        Input::Orphaned { .. } => "Orphaned",
        Input::Heard { .. } => "Heard",
        Input::Disconnect { .. } => "Disconnect",
        Input::Dead { .. } => "Dead",
        Input::Admin { .. } => "Admin",
        Input::Sent { .. } => "Sent",
        Input::SendFailed { .. } => "SendFailed",
        Input::Unsendable { .. } => "Unsendable",
        Input::Moved { .. } => "Moved",
        Input::Switched { .. } => "Switched",
        Input::Released { .. } => "Released",
        Input::Capable { .. } => "Capable",
        Input::State { .. } => "State",
    }
}

impl Node {
    /// Hand the shadow core `input`, which a decision site built after its
    /// own decision. Nothing the core decides is carried out but the
    /// shadow's own bookkeeping of its leases and link numbers, so nothing is
    /// returned: the outputs hold the shadow's leases. The shadow takes what
    /// a test planted or set past the writers first
    /// ([`Node::shadow_resync`]). Feeding the shadow writes nothing of the
    /// node's, so it moves no outcome of the node's.
    /// The one caller, with [`Node::decide_at`], of the shadow's
    /// [`Table::step`].
    pub(in crate::node) fn decide(&mut self, input: Input) {
        self.decide_at(None, input);
    }

    /// [`Node::decide`] for an input that opens a link, a dial or a msg1,
    /// on the node's link `at`, which the core's number for it then names.
    pub(in crate::node) fn decide_at(&mut self, at: Option<LinkId>, input: Input) {
        self.shadow_resync(at);
        self.shadow.fed.extend(at);
        self.shadow.count(kind(&input));
        let me = *self.node_addr();
        let params = super::params::leg_params(&self.config().node);
        self.shadow.me = Some(me);
        let now = self.shadow.now();
        let table = self
            .shadow
            .table
            .get_or_insert_with(|| Table::new(me, params));
        let out = table.step(input, now);
        self.shadow.decided(&out);
        self.shadow.settle(at, out);
    }

    /// [`Node::decide_at`] at `ms` on the interval clock rather than at the
    /// clock's now: for an input that opens a handshake leg the node stamped
    /// at `ms`, so the core's leg counts its deadline and resends from the
    /// instant the node's does. The work between the node's stamp and its
    /// input, a Noise step among it, can outlast the comparison's skew on a
    /// loaded host.
    pub(in crate::node) fn decide_stamped(&mut self, at: Option<LinkId>, input: Input, ms: u64) {
        let clock = self.shadow.clock.replace(ms);
        self.decide_at(at, input);
        self.shadow.clock = clock;
    }

    /// Note that a test planted a dial's leg on the node's link `id` past
    /// the dial site, which the shadow mirrors at its resync.
    pub(in crate::node) fn shadow_planted(&mut self, id: LinkId) {
        self.shadow.planted.insert(id);
    }

    /// Take from the shadow the dial's leg on the node's link `id`, which a
    /// test ended past the writers, as the node's own leg was taken.
    /// Nothing when the shadow does not number the link or holds no leg.
    pub(in crate::node) fn shadow_forget(&mut self, id: LinkId) {
        self.shadow.planted.remove(&id);
        let Some(no) = self.shadow.nos.get(&id).copied() else {
            return;
        };
        let Some(table) = self.shadow.table.as_mut() else {
            return;
        };
        if let Some(old) = table.take_leg(no) {
            let _ = old.release();
            self.shadow.leases.freed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Move the deadline and next resend of the shadow's leg on the node's
    /// link `id` later by `by`, as for a dial the core took that long after
    /// the node stamped it.
    pub(in crate::node) fn shadow_delay(&mut self, id: LinkId, by: std::time::Duration) {
        let Some(link) = self.shadow_link(id) else {
            return;
        };
        let Some(table) = self.shadow.table.as_mut() else {
            return;
        };
        let Some(leg) = table.legs().get(link) else {
            return;
        };
        let later = |at: PeerInstant| fips_core::time::Instant::checked_add(at, by).unwrap_or(at);
        let (deadline, next) = (later(leg.deadline()), leg.next_resend().map(later));
        table.replant_leg(link, deadline, next);
    }

    /// Have the shadow decide at `ms` on the interval clock, the instant
    /// the node's timers are running at, until it is called with `None`.
    pub(in crate::node) fn shadow_clock(&mut self, ms: Option<u64>) {
        self.shadow.clock = ms;
    }

    /// Record what the node did, in the words it shares with the core, for
    /// the live audit's comparison with what the shadow decided.
    pub(in crate::node) fn did(&self, did: Did) {
        let mut logs = self.shadow.logs.lock().unwrap_or_else(|e| e.into_inner());
        logs.node.push(did);
    }

    /// Record that the node closed the connection at `addr` on `transport`,
    /// for the live audit's comparison with the connections the shadow core
    /// decided to close (`closes-agree`). Each of the node's close sites
    /// that a decision reaches calls it where it closes.
    pub(in crate::node) fn closed(&self, transport: TransportId, addr: &TransportAddr) {
        let mut closes = self.shadow.closes.lock().unwrap_or_else(|e| e.into_inner());
        closes.node.push(pair(transport, addr));
    }

    /// Tell the shadow the node gave up unfinished the dial or leg on its
    /// link `id`, for a cause the core has no timer of its own for: a
    /// connection that failed or was abandoned, a dial whose msg1 could not
    /// be built, a failed leg, a traversal's adoption, a test; an answer
    /// whose msg2 could not be sent goes to [`Node::shadow_unsendable`].
    /// A leg the node reaps at its deadline goes to [`Node::shadow_reap`]
    /// instead. Nothing when the shadow does not number the link.
    pub(in crate::node) fn shadow_abandon(&mut self, id: LinkId) {
        if let Some(link) = self.shadow_link(id) {
            self.decide(Input::ConnectFailed { link });
        }
    }

    /// Tell the shadow the node gave up the answer on its link `id`, whose
    /// msg2 could not be sent for a cause no resend outlasts, and closed
    /// nothing. Nothing when the shadow does not number the link.
    pub(in crate::node) fn shadow_unsendable(&mut self, id: LinkId) {
        if let Some(link) = self.shadow_link(id) {
            self.decide(Input::Unsendable { link });
        }
    }

    /// Give the shadow core its own reap of the leg on the node's link
    /// `id`, which the node is reaping at its handshake deadline: the core
    /// reaps the leg, by the reap its poll makes, if its own deadline falls
    /// within [`LEG_SKEW_MS`](super::audit::LEG_SKEW_MS) of the instant
    /// the node reaps at, since each side stamped the leg at its own site a
    /// little apart. A leg the core still holds then is the comparison's to
    /// find: the node's give-up is not fed in its place. Nothing when the
    /// shadow does not number the link or holds no leg on it.
    pub(in crate::node) fn shadow_reap(&mut self, id: LinkId) {
        let Some(link) = self.shadow_link(id) else {
            return;
        };
        let skew = std::time::Duration::from_millis(super::audit::LEG_SKEW_MS);
        let at = self.shadow.now();
        let at = fips_core::time::Instant::checked_add(at, skew).unwrap_or(at);
        let Some(table) = self.shadow.table.as_mut() else {
            return;
        };
        let out = table.reap_leg(link, at);
        self.shadow.decided(&out);
        self.shadow.settle(None, out);
    }

    /// Tell the shadow the node removed `peer` for `why`, where the removal
    /// is an input of its own: a rekey teardown, an orphaned bundle, a
    /// `Disconnect`, a dead link or the operator. A restart, a replacement
    /// and an own-dial restart are part of the msg1 or msg2 that caused
    /// them, which the shadow is fed instead, and the node's own close
    /// removes nothing the shadow is told of.
    pub(in crate::node) fn shadow_remove(&mut self, peer: NodeAddr, why: Why) {
        let input = match why {
            Why::Ended => Input::Ended { peer },
            Why::Orphaned => Input::Orphaned { peer },
            Why::Disconnect => Input::Disconnect { peer },
            Why::Dead => Input::Dead { peer },
            Why::Admin => Input::Admin { peer },
            // A redial's swap is part of the frame that proved it.
            Why::Restart | Why::Replacement | Why::Redial | Why::OwnRestart | Why::Closed => return,
        };
        self.decide(input);
    }

    /// Tell the shadow the node refused, after the core asked for its
    /// answer, the msg1 that opened its link `id`: its late ACL refused it,
    /// or no session index was left to draw. Nothing when the shadow did not
    /// ask about the link.
    pub(in crate::node) fn shadow_unasked(&mut self, id: LinkId) {
        if let Some(link) = self.shadow_link(id) {
            self.decide(Input::Abandon { link });
        }
    }

    /// Hand the shadow the msg2 `msg2` the node built, under its session
    /// index `index`, for the msg1 that opened its link `id`, which arrived
    /// at `at` on the interval clock: the instant the node's answer leg
    /// counts its deadline from, and the one the shadow decides at, so the
    /// core's leg counts from it too. Nothing when the shadow did not ask
    /// about the link.
    pub(in crate::node) fn shadow_hello(&mut self, id: LinkId, index: u32, msg2: &[u8], at: u64) {
        if let Some(link) = self.shadow_link(id) {
            let lease = self.shadow.lease(index);
            let hello = crate::proto::settle::input::Hello {
                link,
                msg2: msg2.to_vec(),
                lease,
            };
            self.decide_stamped(None, Input::Hello(hello), at);
        }
    }

    /// Tell the shadow the msg2 or msg1 resend the leg on the node's link
    /// `id` sent went out (`ok`) or failed. Nothing when the shadow does not
    /// number the link.
    pub(in crate::node) fn shadow_sent(&mut self, id: LinkId, ok: bool) {
        if let Some(link) = self.shadow_link(id) {
            self.decide(if ok {
                Input::Sent { link }
            } else {
                Input::SendFailed { link }
            });
        }
    }

    /// Hand the shadow a path input the node's own link records took,
    /// `input`, which names the node's record number for the link: the same
    /// input, naming the shadow's number for that link. Nothing for a link
    /// the shadow does not number, and nothing for an input that is not a
    /// path input.
    pub(in crate::node) fn shadow_feed(&mut self, input: &Input) {
        let to = |named: LinkNo| self.links.id(named).and_then(|id| self.shadow.no(id));
        let input = match input {
            Input::Moved {
                link,
                from,
                to: at,
                roam,
            } => to(*link).map(|link| Input::Moved {
                link,
                from: from.clone(),
                to: at.clone(),
                roam: *roam,
            }),
            Input::Switched {
                link,
                to: at,
                proven,
            } => to(*link).map(|link| Input::Switched {
                link,
                to: at.clone(),
                proven: *proven,
            }),
            Input::Released { link, pair, keep } => to(*link).map(|link| Input::Released {
                link,
                pair: pair.clone(),
                keep: *keep,
            }),
            Input::Capable { link } => to(*link).map(|link| Input::Capable { link }),
            Input::State { link, pair, proven } => to(*link).map(|link| Input::State {
                link,
                pair: pair.clone(),
                proven: *proven,
            }),
            _ => None,
        };
        if let Some(input) = input {
            self.decide(input);
        }
    }

    /// Write into the shadow what a test built past the decision sites, and
    /// what a test setter changed, before the shadow next decides. On a node
    /// a test planted past its writers: a record, held as a leg at its setup
    /// pair, for each link the shadow does not number, and each index entry
    /// at a pair no record of the shadow names, named there through its
    /// link's record ([`Links::name`](crate::proto::settle::links::Links::name)),
    /// or as the setup pair of a record opened for a link with none. On any node: each held peer the shadow does not hold, from
    /// the peer's facts ([`held`]), where the node is planted or the shadow
    /// numbers no link of the peer's, and on a planted node each peer a
    /// test planted afresh on a link the shadow does not number, over one
    /// the shadow holds, the record it held the peer on going when the
    /// node's map lacks that link; and a leg, under a lease of the index
    /// the machine holds and reaped and resent at the machine's own instants
    /// ([`leg_times`](super::audit::leg_times)), for each handshake machine
    /// on a link the shadow numbers not, or on a planted node holds no leg
    /// or peer on, but the link `except` an input is opening. A test helper that builds a
    /// handshake or a peer through the writers but past the sites (a seeded
    /// machine, a peer installed directly) is so taken as a plant is. And
    /// each peer a test mutator or setter flagged
    /// ([`ActivePeer::past_feed`](crate::peer::ActivePeer::past_feed)) has
    /// its record's paths and capability, and its epoch, heard flag and
    /// instants, written from the peer. Last, on any node, each link the
    /// node's table records that nothing above took, which a test opened
    /// through the writers but past the sites (a dial noted with no
    /// handshake of its own), gets a record held as a leg at its setup
    /// pair. A link a decision site named as the one its input opens, and a
    /// link whose record the shadow retired while the node still holds it,
    /// is never taken, nor a peer on such a link: what the core made of it
    /// is the comparison's to read. Nothing a writer set is overwritten
    /// otherwise, and no flag is cleared: the node's own resync clears them.
    pub(in crate::node) fn shadow_resync(&mut self, except: Option<LinkId>) {
        // The mutation lane's break: nothing planted reaches the shadow.
        if node_fault!(PlantSkipped) {
            return;
        }
        let planted = self.planted();
        let me = *self.node_addr();
        let params = super::params::leg_params(&self.config().node);
        let rate = &self.config().node.rate_limit;
        let (max, timeout) = (
            rate.handshake_max_resends,
            rate.handshake_timeout_secs * 1000,
        );
        let now = self.shadow.now();
        let shadow = &mut self.shadow;
        let table = shadow.table.get_or_insert_with(|| Table::new(me, params));
        // A leg the shadow reaped by its own timers is not the node's plant
        // while the node, later in the same entry, still holds it.
        shadow.reaped.retain(|id| self.links.contains_key(id));
        if planted {
            let mut links: Vec<(LinkId, Pair, Dir)> = self
                .links
                .iter()
                .filter(|(id, _)| !shadow.nos.contains_key(id) && !shadow.reaped.contains(id))
                .map(|(id, link)| (*id, setup(link), dir(link)))
                .collect();
            links.sort_by_key(|(id, _, _)| id.as_u64());
            for (id, at, dir) in links {
                let no = table.records().open(at, dir, Holder::Leg);
                shadow.nos.insert(id, no);
            }
            let mut entries: Vec<(Pair, LinkId)> = self
                .links
                .index()
                .iter()
                .map(|((tid, addr), id)| (pair(*tid, addr), *id))
                .collect();
            entries.sort_by(|(a, x), (b, y)| a.cmp(b).then(x.as_u64().cmp(&y.as_u64())));
            for (at, id) in entries {
                if table.records().at(&at).next().is_some() || shadow.reaped.contains(&id) {
                    continue;
                }
                match shadow.nos.get(&id) {
                    // Named through the record, as the node's own records
                    // name it, not as a path the link's bundle does not
                    // hold.
                    Some(no) => {
                        let records = table.records();
                        let mut named = records.names().clone();
                        named.insert((at, *no));
                        records.name(named);
                    }
                    None => {
                        let no = table.records().open(at, Dir::Inbound, Holder::Leg);
                        shadow.nos.insert(id, no);
                    }
                }
            }
        }
        for (addr, peer) in self.peers.iter() {
            // A peer a test planted afresh, over one the shadow holds, on a
            // link the shadow does not number is taken again from its
            // facts: the node holds it there now, not where the shadow
            // holds it.
            let replanted = planted && !shadow.nos.contains_key(&peer.link_id());
            let taken = table.held(addr).is_some() && !replanted;
            if taken || shadow.reaped.contains(&peer.link_id()) {
                continue;
            }
            // The link the shadow held such a peer on goes with it when the
            // node holds no such link: only the plant it replaces named it.
            let left = table.held(addr).map(|h| h.link).and_then(|no| {
                let id = shadow
                    .nos
                    .iter()
                    .find_map(|(id, n)| (*n == no).then_some(*id));
                id.filter(|id| !self.links.contains_key(id))
                    .map(|id| (id, no))
            });
            if let Some((id, no)) = left {
                let _ = table.records().retire(no);
                shadow.nos.remove(&id);
            }
            let link = match shadow.nos.get(&peer.link_id()) {
                Some(no) if planted => *no,
                Some(_) => continue,
                None => {
                    let (at, dir) = self
                        .links
                        .get(&peer.link_id())
                        .map_or((current(peer), Dir::Inbound), |l| (setup(l), dir(l)));
                    let no = table.records().open(at, dir, Holder::Leg);
                    shadow.nos.insert(peer.link_id(), no);
                    no
                }
            };
            table.plant(*addr, held(peer, link));
            // The link's record takes the paths of the peer's bundle, as the
            // node's own record of it took them from the bundle's feed.
            let capable = peer.bundle().is_some_and(|b| b.capable());
            table.records().resync(link, super::recorded(peer), capable);
        }
        let holding: Vec<LinkNo> = self
            .peers
            .values()
            .filter_map(|p| shadow.nos.get(&p.link_id()).copied())
            .collect();
        // Each handshake the node carries: its leg in the node's legs, or
        // one a machine carries with no leg there, with its lease's index,
        // the identity it dialed or learned, its msg1, the msg2 an answer
        // stored, and the instants it is reaped and next resends at.
        let at = crate::time::at::<crate::time::HostClock>;
        let mut carried: Vec<Carried> = self
            .legs
            .iter()
            .filter_map(|leg| {
                let id = self.links.id(leg.link())?;
                let msg2 = match leg.kind() {
                    crate::proto::settle::legs::Kind::Answer { msg2 } => Some(msg2.clone()),
                    crate::proto::settle::legs::Kind::Dial => None,
                };
                Some((
                    id,
                    leg.index(),
                    leg.peer(),
                    leg.msg1().to_vec(),
                    msg2,
                    leg.deadline(),
                    leg.next_resend(),
                ))
            })
            .collect();
        for (id, machine) in self.peer_machines.iter() {
            if machine.leg().is_none() || carried.iter().any(|c| c.0 == *id) {
                continue;
            }
            let Some(index) = machine.our_index() else {
                continue;
            };
            let msg2 = (!machine.conn_is_outbound())
                .then(|| machine.conn_handshake_msg2().unwrap_or_default().to_vec());
            // The planted handshake keeps its machine's instants, as the
            // node reaps it by them, rather than a full timeout from the
            // resync.
            let (deadline, _) = super::audit::leg_times(max, timeout, machine);
            carried.push((
                *id,
                index.as_u32(),
                machine.conn_expected_identity().map(|i| *i.node_addr()),
                machine.conn_handshake_msg1().unwrap_or_default().to_vec(),
                msg2,
                at(deadline),
                None,
            ));
        }
        carried.sort_by_key(|c| c.0.as_u64());
        for (id, index, peer, msg1, msg2, deadline, next) in carried {
            if Some(id) == except || shadow.reaped.contains(&id) {
                continue;
            }
            let no = match shadow.nos.get(&id) {
                Some(no) if planted => *no,
                Some(_) => continue,
                None => {
                    let Some(link) = self.links.get(&id) else {
                        continue;
                    };
                    let no = table.records().open(setup(link), dir(link), Holder::Leg);
                    shadow.nos.insert(id, no);
                    no
                }
            };
            if holding.contains(&no) || table.legs().get(no).is_some() {
                continue;
            }
            shadow.leases.minted.fetch_add(1, Ordering::Relaxed);
            let start = Start {
                link: no,
                peer,
                msg1,
                lease: IndexLease::for_test(index),
                resends: None,
                held: None,
            };
            if let Some(old) = table.plant_leg(start, msg2, now) {
                let _ = old.release();
                shadow.leases.freed.fetch_add(1, Ordering::Relaxed);
            }
            // The planted handshake keeps the node's instants, as the node
            // reaps it and resends its msg1 by them, rather than a full
            // timeout and resend interval from the resync.
            table.replant_leg(no, deadline, next);
        }
        // A link a test opened through the node's writers but past every
        // decision site (a dial noted with no handshake of its own) is
        // taken as a plant's is, on any node, once nothing above took it.
        let mut opened: Vec<(LinkId, Pair, Dir)> = self
            .links
            .iter()
            .filter(|(id, _)| {
                Some(**id) != except
                    && !shadow.nos.contains_key(id)
                    && !shadow.reaped.contains(id)
                    && !shadow.fed.contains(id)
                    && self.links.no(id).is_some()
            })
            .map(|(id, link)| (*id, setup(link), dir(link)))
            .collect();
        opened.sort_by_key(|(id, _, _)| id.as_u64());
        for (id, at, dir) in opened {
            let no = table.records().open(at, dir, Holder::Leg);
            shadow.nos.insert(id, no);
        }
        // A dial's leg a test planted on a link the shadow already numbers,
        // or a peer holds: the shadow takes it once, at the first resync
        // that numbers its link, and from then on holds it as it holds any
        // other leg, so the comparison sees what each side made of it. A
        // test that ends it past the writers tells the shadow at once
        // ([`Node::shadow_forget`]).
        let mut planted: Vec<LinkId> = shadow.planted.iter().copied().collect();
        planted.sort_by_key(|id| id.as_u64());
        for id in planted {
            let Some(no) = shadow.nos.get(&id).copied() else {
                continue;
            };
            shadow.planted.remove(&id);
            let Some(leg) = self.links.no(&id).and_then(|n| self.legs.get(n)) else {
                continue;
            };
            if table.legs().get(no).is_some() {
                continue;
            }
            shadow.leases.minted.fetch_add(1, Ordering::Relaxed);
            let start = Start {
                link: no,
                peer: leg.peer(),
                msg1: leg.msg1().to_vec(),
                lease: IndexLease::for_test(leg.index()),
                resends: None,
                held: None,
            };
            if let Some(old) = table.plant_leg(start, None, now) {
                let _ = old.release();
                shadow.leases.freed.fetch_add(1, Ordering::Relaxed);
            }
            table.replant_leg(no, leg.deadline(), leg.next_resend());
        }
        let flagged = self.peers.iter().filter(|(_, p)| p.past_feed());
        for (addr, peer) in flagged {
            let Some(no) = shadow.nos.get(&peer.link_id()).copied() else {
                continue;
            };
            let capable = peer.bundle().is_some_and(|b| b.capable());
            table.records().resync(no, super::recorded(peer), capable);
            if let Some(h) = table.held(addr) {
                let mut h = h.clone();
                let facts = held(peer, h.link);
                h.epoch = facts.epoch;
                h.heard = facts.heard;
                h.installed = facts.installed;
                h.last = facts.last;
                table.plant(*addr, h);
            }
        }
    }

    /// Give the shadow's restart gates what a test wrote into the node's
    /// own gate memory past its decisions, through the gates' writers:
    /// `write` takes the gates, the instant the shadow decides at and the
    /// table's parameters.
    pub(in crate::node) fn shadow_gates(
        &mut self,
        write: impl FnOnce(
            &mut crate::proto::settle::gates::Gates<PeerInstant>,
            PeerInstant,
            &crate::proto::settle::params::Params,
        ),
    ) {
        self.shadow_resync(None);
        let now = self.shadow.now();
        if let Some(table) = self.shadow.table.as_mut() {
            let (gates, params) = table.gates_mut();
            write(gates, now, params);
        }
    }

    /// The shadow's number for the node's link `id`, once it has taken
    /// what a test built past the decision sites ([`Node::shadow_resync`]).
    pub(in crate::node) fn shadow_link(&mut self, id: LinkId) -> Option<LinkNo> {
        self.shadow_resync(None);
        self.shadow.no(id)
    }

    /// Run the shadow core's legs' timers now, as [`Node::decide`] runs an
    /// input. The one caller of the shadow's [`Table::poll`].
    pub(in crate::node) fn shadow_tick(&mut self) {
        self.shadow_resync(None);
        self.shadow.count("tick");
        let now = self.shadow.now();
        let Some(table) = self.shadow.table.as_mut() else {
            return;
        };
        let out = table.poll(now);
        self.shadow.decided(&out);
        self.shadow.settle(None, out);
    }
}

#[cfg(test)]
#[path = "tests/decide.rs"]
mod tests;
