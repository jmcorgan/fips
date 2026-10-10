//! Virtual IP pool manager.
//!
//! Manages allocation, TTL, and reclamation of virtual IPv6 addresses
//! from a configured CIDR range. Tracks mapping state and integrates
//! with conntrack to determine active sessions.

use crate::NodeAddr;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Most live mappings the pool holds before it refuses new names.
///
/// Every mapping adds rules to the NAT table, which is rebuilt whole on each
/// change, and work to every tick and to shutdown, so this bounds all three.
pub const MAPPING_CEILING: usize = 1000;

/// New mappings the pool admits in a burst, when idle long enough to refill.
pub const MAPPING_BURST: u32 = 50;

/// New mappings per second the pool admits once a burst is spent.
pub const MAPPING_RATE: u32 = 10;

/// Errors from pool operations.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("invalid CIDR: {0}")]
    InvalidCidr(String),
    #[error("pool exhausted ({0} addresses in use)")]
    Exhausted(usize),
    #[error("prefix length must be between 1 and 127")]
    InvalidPrefix,
    #[error("live-mapping ceiling reached ({0} mappings)")]
    AtCeiling(usize),
    #[error("new-mapping rate limit reached")]
    RateLimited,
    #[error("pool state write not yet confirmed")]
    AwaitingMark,
    #[error("mesh address {0} lies inside the pool prefix")]
    InsidePool(Ipv6Addr),
}

impl PoolError {
    /// A short name for the error, for structured log fields.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::AtCeiling(_) => "ceiling",
            Self::RateLimited => "rate-limited",
            Self::Exhausted(_) => "exhausted",
            Self::AwaitingMark => "awaiting-mark",
            Self::InsidePool(_) => "inside-pool",
            Self::InvalidCidr(_) | Self::InvalidPrefix => "invalid",
        }
    }
}

/// State of a virtual IP mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingState {
    /// Allocated via DNS query, no NAT sessions yet.
    Allocated,
    /// Active NAT sessions exist.
    Active,
    /// TTL expired but sessions remain.
    Draining,
}

/// A single virtual IP ↔ FIPS mesh address mapping.
#[derive(Debug, Clone)]
pub struct VirtualIpMapping {
    /// The FIPS node address this mapping is for.
    pub node_addr: NodeAddr,
    /// The virtual IP allocated from the pool.
    pub virtual_ip: Ipv6Addr,
    /// The FIPS mesh address (fd00::/8).
    pub mesh_addr: Ipv6Addr,
    /// The DNS name that was queried (e.g. "npub1abc...xyz.fips").
    pub dns_name: String,
    /// Current state.
    pub state: MappingState,
    /// When this mapping was created.
    pub created: Instant,
    /// When this mapping was last referenced (DNS query or session).
    pub last_referenced: Instant,
    /// When draining started (for grace period tracking).
    pub drain_start: Option<Instant>,
    /// Number of active conntrack sessions.
    pub session_count: u32,
    /// Whether a reply from `mesh_addr` has been seen on a flow to
    /// `virtual_ip`. Only such a mapping is refreshed by re-queries and kept
    /// at the ceiling. Never cleared.
    pub used: bool,
    /// Created while conntrack evidence was not trusted, or before a started
    /// pool had taken `MAX_ABSENT_READS` reads, so it can never become used:
    /// a binding left from an earlier holder of the address could not be
    /// told from its own traffic.
    pub blind: bool,
    /// When every answer given at creation has expired: created plus the
    /// TTL plus the grace period.
    pub answer_deadline: Instant,
    /// When an answer last named this mapping's address.
    pub last_answer: Instant,
}

/// Events emitted by the pool on state transitions.
#[derive(Debug)]
pub enum PoolEvent {
    /// A new mapping was allocated — NAT rules should be created.
    MappingCreated {
        virtual_ip: Ipv6Addr,
        mesh_addr: Ipv6Addr,
    },
    /// A mapping was reclaimed — NAT rules should be removed.
    MappingRemoved {
        virtual_ip: Ipv6Addr,
        mesh_addr: Ipv6Addr,
    },
}

/// Pool utilization summary.
#[derive(Debug, Clone)]
pub struct PoolStatus {
    pub total: usize,
    pub allocated: usize,
    pub active: usize,
    pub draining: usize,
    pub free: usize,
    /// Mappings replaced at the ceiling since start.
    pub evicted: u64,
    /// Addresses neither mapped nor free: removed and waiting until no
    /// answer or connection-tracking entry can still name them, or held from
    /// the previous run.
    pub releasing: usize,
    /// New names refused at the ceiling, by exhaustion or while waiting for
    /// a state write, since start.
    pub refused: u64,
}

/// Summary of a single mapping for display.
#[derive(Debug, Clone)]
pub struct MappingInfo {
    pub virtual_ip: Ipv6Addr,
    pub mesh_addr: Ipv6Addr,
    pub node_addr: NodeAddr,
    pub dns_name: String,
    pub state: MappingState,
    pub session_count: u32,
    pub age_secs: u64,
    pub last_ref_secs: u64,
    pub used: bool,
}

/// Path the conntrack table is read from when the kernel provides it.
///
/// A kernel built without `CONFIG_NF_CONNTRACK_PROCFS` has no such file;
/// `SystemConntrack` then dumps the table over netlink instead.
const CONNTRACK_PROC_PATH: &str = "/proc/net/nf_conntrack";

/// Active conntrack sessions counted by destination address.
///
/// Taken once per tick, so the pool does a map lookup per mapping instead of
/// reading and scanning the whole conntrack table per mapping under its lock.
///
/// `read` says whether the snapshot came from a successful read. The default
/// snapshot, which stands in for a failed read, is not read.
#[derive(Debug, Clone, Default)]
pub struct ConntrackSnapshot {
    sessions: HashMap<Ipv6Addr, u32>,
    /// Original destination to the reply-tuple sources of every entry.
    bindings: HashMap<Ipv6Addr, HashSet<Ipv6Addr>>,
    /// The same, for entries that have seen a reply.
    replied: HashMap<Ipv6Addr, HashSet<Ipv6Addr>>,
    /// Whether the snapshot is the result of a successful read.
    pub read: bool,
}

impl ConntrackSnapshot {
    /// Build a read snapshot from counts already keyed by destination address.
    pub fn from_counts(sessions: HashMap<Ipv6Addr, u32>) -> Self {
        Self {
            sessions,
            read: true,
            ..Self::default()
        }
    }

    /// Record that an entry with original destination `orig_dst` has reply
    /// source `reply_src`, and whether it has seen a reply.
    pub fn record_binding(&mut self, orig_dst: Ipv6Addr, reply_src: Ipv6Addr, replied: bool) {
        self.bindings.entry(orig_dst).or_default().insert(reply_src);
        if replied {
            self.replied.entry(orig_dst).or_default().insert(reply_src);
        }
    }

    /// A read snapshot with no entries, to fill with `record_binding` and
    /// `add_session`.
    pub fn empty_read() -> Self {
        Self {
            read: true,
            ..Self::default()
        }
    }

    /// Count one more entry naming `addr` among its destinations.
    pub fn add_session(&mut self, addr: Ipv6Addr) {
        *self.sessions.entry(addr).or_insert(0) += 1;
    }

    /// Whether an entry addressed to `orig_dst` has its reply tuple from
    /// `reply_src`, replied or not.
    pub fn bound_to(&self, orig_dst: Ipv6Addr, reply_src: Ipv6Addr) -> bool {
        self.bindings
            .get(&orig_dst)
            .is_some_and(|sources| sources.contains(&reply_src))
    }

    /// Whether an entry addressed to `virtual_ip` has seen a reply from
    /// `mesh_addr`, which is not the virtual IP itself.
    pub fn replied_from(&self, virtual_ip: Ipv6Addr, mesh_addr: Ipv6Addr) -> bool {
        mesh_addr != virtual_ip
            && self
                .replied
                .get(&virtual_ip)
                .is_some_and(|sources| sources.contains(&mesh_addr))
    }

    /// Sessions whose destination is `virtual_ip`, or zero if there are none.
    pub fn sessions_for(&self, virtual_ip: Ipv6Addr) -> u32 {
        self.sessions.get(&virtual_ip).copied().unwrap_or(0)
    }

    /// Number of distinct destination addresses the snapshot saw.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the snapshot saw no sessions at all.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

/// Trait for taking a conntrack session snapshot.
pub trait ConntrackQuerier: Send + Sync {
    /// Read the conntrack table once and count sessions by destination.
    fn snapshot(&self) -> Result<ConntrackSnapshot, std::io::Error>;
}

/// Conntrack querier that parses /proc/net/nf_conntrack.
pub struct ProcConntrack;

impl ConntrackQuerier for ProcConntrack {
    fn snapshot(&self) -> Result<ConntrackSnapshot, std::io::Error> {
        let content = std::fs::read_to_string(CONNTRACK_PROC_PATH)?;
        Ok(parse_conntrack(&content))
    }
}

/// Where a conntrack snapshot was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackSource {
    /// `/proc/net/nf_conntrack`.
    Proc,
    /// A conntrack table dump over `NETLINK_NETFILTER`.
    Netlink,
}

impl ConntrackSource {
    /// Short name of the source.
    pub fn name(self) -> &'static str {
        match self {
            Self::Proc => "proc",
            Self::Netlink => "netlink",
        }
    }
}

/// Why no conntrack source could be read.
#[derive(Debug)]
pub struct ConntrackUnreadable {
    /// The error reading `/proc/net/nf_conntrack`.
    pub proc: std::io::Error,
    /// The error from the netlink dump, when the proc file was absent and the
    /// dump was tried.
    pub netlink: Option<std::io::Error>,
}

impl ConntrackUnreadable {
    /// The error that stands for the whole failed read.
    ///
    /// When the dump was tried, its error is the one that decided the read, so
    /// it sets the kind; the absent proc file is kept in the message. Only a
    /// proc error that stopped the read before the dump stands alone.
    fn into_error(self) -> std::io::Error {
        match self.netlink {
            Some(netlink) => std::io::Error::new(
                netlink.kind(),
                format!("proc: {}; netlink: {netlink}", self.proc),
            ),
            None => self.proc,
        }
    }
}

/// The conntrack reader the gateway uses, which also says which source
/// answered.
///
/// The per-tick read and the startup probe both go through this type, so the
/// probe cannot report a source the tick would not use. The queriers are type
/// parameters so tests can substitute fakes.
///
/// The proc file is read first. Only when it is absent is the table dumped
/// over netlink, and that is decided on every read: the file appears once
/// `nf_conntrack` is loaded in the namespace, so a choice fixed at startup
/// could keep using netlink on a kernel that has the file.
pub struct SystemConntrack<P = ProcConntrack, N = super::conntrack::NetlinkConntrack> {
    proc: P,
    netlink: N,
}

impl<P: ConntrackQuerier, N: ConntrackQuerier> SystemConntrack<P, N> {
    /// A reader over the given proc and netlink queriers.
    pub fn new(proc: P, netlink: N) -> Self {
        Self { proc, netlink }
    }

    /// Read conntrack once and say which source the snapshot came from.
    ///
    /// A proc error other than an absent file, such as a permission error, is
    /// returned without trying netlink.
    pub fn read(&self) -> Result<(ConntrackSource, ConntrackSnapshot), ConntrackUnreadable> {
        match self.proc.snapshot() {
            Ok(snapshot) => Ok((ConntrackSource::Proc, snapshot)),
            Err(proc) if proc.kind() == std::io::ErrorKind::NotFound => {
                match self.netlink.snapshot() {
                    Ok(snapshot) => Ok((ConntrackSource::Netlink, snapshot)),
                    Err(netlink) => Err(ConntrackUnreadable {
                        proc,
                        netlink: Some(netlink),
                    }),
                }
            }
            Err(proc) => Err(ConntrackUnreadable {
                proc,
                netlink: None,
            }),
        }
    }
}

impl Default for SystemConntrack {
    fn default() -> Self {
        Self::new(ProcConntrack, super::conntrack::NetlinkConntrack)
    }
}

impl<P: ConntrackQuerier, N: ConntrackQuerier> ConntrackQuerier for SystemConntrack<P, N> {
    fn snapshot(&self) -> Result<ConntrackSnapshot, std::io::Error> {
        self.read()
            .map(|(_, snapshot)| snapshot)
            .map_err(ConntrackUnreadable::into_error)
    }
}

/// Outcome of the startup check for a readable conntrack source.
#[derive(Debug)]
pub enum ConntrackProbe {
    /// Sessions can be read, from this source.
    Found(ConntrackSource),
    /// No source can be read, so every mapping reads zero sessions and session
    /// pinning is off.
    Missing(ConntrackUnreadable),
}

/// Read conntrack once, as a tick would, and report which source answered.
pub fn probe_conntrack<P: ConntrackQuerier, N: ConntrackQuerier>(
    reader: &SystemConntrack<P, N>,
) -> ConntrackProbe {
    match reader.read() {
        Ok((source, _)) => ConntrackProbe::Found(source),
        Err(e) => ConntrackProbe::Missing(e),
    }
}

/// Read the conntrack lines of `/proc/net/nf_conntrack` into a snapshot.
///
/// Every address is parsed as an address and compared as an address. The
/// kernel prints tuples as `src=%pI6 dst=%pI6`, the full uncompressed form with
/// leading zeros, so a session to `fd01::1` is written
/// `dst=fd01:0000:0000:0000:0000:0000:0000:0001`; the previous code searched
/// each line for the address's compressed `Display` form, which cannot occur in
/// a fixed-width field, so it counted nothing on any kernel.
///
/// A conntrack line carries the original and the reply tuple, each with its own
/// `dst=`, and the line is counted once per distinct address among them. That
/// keeps the meaning the count had before, which was "this line mentions the
/// address". A value that does not parse as an IPv6 address is skipped, which
/// is how IPv4 lines and any future field are ignored.
///
/// The first `src=`/`dst=` pair is the original tuple and the second the
/// reply tuple. Each line also records its binding, from the original
/// destination to the reply source, and whether it has seen a reply: the
/// kernel marks a line that has not with `[UNREPLIED]`.
fn parse_conntrack(content: &str) -> ConntrackSnapshot {
    let mut snapshot = ConntrackSnapshot {
        read: true,
        ..ConntrackSnapshot::default()
    };
    let mut seen: HashSet<Ipv6Addr> = HashSet::new();

    for line in content.lines() {
        seen.clear();
        let mut sources = Vec::new();
        let mut destinations = Vec::new();
        for token in line.split_whitespace() {
            if let Some(value) = token.strip_prefix("dst=") {
                let addr = value.parse::<Ipv6Addr>().ok();
                if let Some(addr) = addr {
                    seen.insert(addr);
                }
                destinations.push(addr);
            } else if let Some(value) = token.strip_prefix("src=") {
                sources.push(value.parse::<Ipv6Addr>().ok());
            }
        }
        for addr in &seen {
            *snapshot.sessions.entry(*addr).or_insert(0) += 1;
        }
        if let (Some(Some(orig_dst)), Some(Some(reply_src))) =
            (destinations.first(), sources.get(1))
        {
            let replied = !line.split_whitespace().any(|t| t == "[UNREPLIED]");
            snapshot.record_binding(*orig_dst, *reply_src, replied);
        }
    }

    snapshot
}

/// Whether a conntrack read outcome is new or a repeat of the last one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadReport {
    /// The outcome differs from the previous read, or is the first.
    Changed,
    /// The same outcome as the previous read.
    Repeated,
}

/// Remembers the last conntrack read outcome.
///
/// When no source is readable, for example a kernel with no
/// `/proc/net/nf_conntrack` whose netlink dump is refused, every read fails
/// the same way and a per-tick warning would repeat for the life of the
/// process. Warning on a change of outcome still separates "the source is
/// unreadable" from "there are no sessions", which the pool could not
/// distinguish before, without filling the log.
#[derive(Debug, Default)]
pub struct ConntrackReadLog {
    last: Option<Option<std::io::ErrorKind>>,
}

impl ConntrackReadLog {
    /// Record a read outcome and say whether it is new.
    ///
    /// `None` is a successful read; `Some(kind)` is a failure of that kind.
    pub fn observe(&mut self, outcome: Option<std::io::ErrorKind>) -> ReadReport {
        let report = if self.last == Some(outcome) {
            ReadReport::Repeated
        } else {
            ReadReport::Changed
        };
        self.last = Some(outcome);
        report
    }
}

/// A virtual IP handed out for a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    /// The address.
    pub virtual_ip: Ipv6Addr,
    /// Whether the mapping was created by this allocation.
    pub is_new: bool,
    /// The TTL the answer carries, in seconds.
    pub ttl: u32,
    /// The mapping this allocation replaced, if any.
    pub evicted: Option<Evicted>,
}

/// A mapping removed to make room for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evicted {
    pub virtual_ip: Ipv6Addr,
    pub mesh_addr: Ipv6Addr,
}

/// What a pool keeps across a restart: no identities, only which offsets a
/// client may still hold an answer for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PoolState {
    /// Format version, 1.
    pub version: u32,
    /// The pool CIDR as configured.
    pub pool: String,
    /// Addresses in the pool.
    pub total: u32,
    /// Offset of the cursor when the state was taken.
    pub from: u32,
    /// Positions, from `from` onward in ring order, that may be issued before
    /// the next state is written; `0..=total`.
    pub span: u32,
    /// Offsets mapped or held when the state was taken, as sorted inclusive
    /// ranges.
    pub held: Vec<[u32; 2]>,
    /// How long, in seconds, a client may hold an answer naming any of them.
    pub hold_secs: u64,
}

/// How a pool begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolStart {
    /// With nothing held, issuing from `offset`.
    Fresh { offset: u32 },
    /// From the state a previous run wrote.
    Restored(PoolState),
}

/// Token bucket for new mappings.
///
/// The level is kept in token-nanoseconds so refill is exact integer
/// arithmetic: one token is `NANOS` units, and each elapsed nanosecond adds
/// `rate` units.
#[derive(Debug)]
struct Bucket {
    /// Current level, in units of `1 / NANOS` token.
    level: u128,
    /// Level when full.
    capacity: u128,
    /// Tokens added per second.
    rate: u128,
    /// When the level was last brought up to date; unset until first use.
    last: Option<Instant>,
}

impl Bucket {
    const NANOS: u128 = 1_000_000_000;

    /// A full bucket of `capacity` tokens refilling at `rate` per second.
    fn new(capacity: u32, rate: u32) -> Self {
        let capacity = u128::from(capacity) * Self::NANOS;
        Self {
            level: capacity,
            capacity,
            rate: u128::from(rate),
            last: None,
        }
    }

    /// Add what has accrued since the last refill, up to capacity.
    fn refill(&mut self, now: Instant) {
        if let Some(last) = self.last {
            let elapsed = now.saturating_duration_since(last).as_nanos();
            self.level = self
                .level
                .saturating_add(elapsed.saturating_mul(self.rate))
                .min(self.capacity);
        }
        // Never move backwards, so a stale `now` cannot credit time twice.
        self.last = Some(self.last.map_or(now, |last| last.max(now)));
    }

    /// Whether at least one whole token is available.
    fn has_token(&self) -> bool {
        self.level >= Self::NANOS
    }

    /// Spend one token; the caller has checked `has_token`.
    fn take(&mut self) {
        self.level = self.level.saturating_sub(Self::NANOS);
    }

    /// Whole tokens available.
    #[cfg(test)]
    fn tokens(&self) -> u128 {
        self.level / Self::NANOS
    }
}

/// Free offsets ahead of the cursor that the pool asks to cover with each
/// state write.
///
/// One tick interval admits at most `MAPPING_BURST + MAPPING_RATE * 10` = 150
/// new names (the tick runs every 10 s), so a write issued at one tick is
/// confirmed long before the stretch it covers runs out; 512 also leaves room
/// for one more write after `MARK_LOW_WATER` fires.
pub const MARK_RESERVE: u32 = 512;

/// Free offsets left before the durable mark below which the next tick asks
/// for a new state write.
///
/// 300 covers a tick gap of 25 s at the full rate with a full bucket
/// (`MAPPING_BURST + MAPPING_RATE * 25` = 300), which allows for a slow
/// conntrack read (2 s per receive) and the write itself ahead of the tick.
pub const MARK_LOW_WATER: u32 = 300;

/// Consecutive read conntrack snapshots after which the pool trusts what they
/// do not show.
///
/// It bounds how many consecutive read snapshots may miss a binding before
/// the pool forgets it, and how many reads a removed address, an address
/// held from the previous run, recovered evidence and a started pool's first
/// mappings that can count traffic each wait for. The
/// legitimate load it must exceed is the partial read: both readers return an
/// interrupted dump or a non-atomic proc read as a successful snapshot, so one
/// read can miss a live entry, and three misses in a row would take three
/// interrupted reads that each skip it. It costs an attacker nothing they
/// control, and legitimate users about 30 s more before a removed address is
/// reused. The value is not measured: no rate of interrupted dumps was
/// observed.
pub const MAX_ABSENT_READS: u32 = 3;

/// Consecutive unread ticks after which the pool stops trusting conntrack
/// evidence.
///
/// It bounds how long the pool trusts what it last read when reads fail.
/// The legitimate load it must exceed is one slow netlink dump (2 s per
/// receive), and three ticks (30 s) is far longer. The cost to an attacker
/// who could make reads fail (none on the LAN side is known) is that mappings
/// created meanwhile cannot become used. The value is chosen, not measured,
/// short enough that releases do not stall for long behind a failed reader.
pub const MAX_UNREAD_TICKS: u32 = 3;

/// How long the pool must refuse nothing before its refusal warning is
/// released with a count of what it refused meanwhile.
pub const BOUND_LOG_HOLD: Duration = Duration::from_secs(60);

/// Whether the durable mark bounds allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkMode {
    /// No state has been written or failed yet; new names wait.
    Pending,
    /// New names are issued only below the durable mark.
    Enforced,
    /// The last write failed, or the pool keeps no state; marks are ignored.
    Ignored,
}

/// The pool's one warning for refusing new names.
///
/// The first refusal of an episode warns; later ones are counted. The episode
/// ends once the pool has refused nothing for `BOUND_LOG_HOLD`, and its count
/// is reported then.
#[derive(Debug, Default)]
struct RefusalLatch {
    /// The last refusal of the current episode and how many it holds.
    open: Option<(Instant, u64)>,
}

impl RefusalLatch {
    /// Count a refusal at `now`; returns whether it opens an episode.
    fn refuse(&mut self, now: Instant) -> bool {
        match &mut self.open {
            Some((last, count)) => {
                *last = (*last).max(now);
                *count += 1;
                false
            }
            None => {
                self.open = Some((now, 1));
                true
            }
        }
    }

    /// Close the episode if nothing was refused for `BOUND_LOG_HOLD` before
    /// `now`, returning its count.
    fn release(&mut self, now: Instant) -> Option<u64> {
        match self.open {
            Some((last, count)) if now.saturating_duration_since(last) >= BOUND_LOG_HOLD => {
                self.open = None;
                Some(count)
            }
            _ => None,
        }
    }
}

/// Whether the pool trusts what conntrack shows.
#[derive(Debug)]
struct Evidence {
    /// Whether replies are counted as use and absent bindings as gone.
    trusted: bool,
    /// Consecutive unread ticks.
    unread: u32,
    /// Consecutive read ticks.
    read: u32,
}

/// An address removed from its mapping, waiting to return to the free set.
#[derive(Debug)]
struct Releasing {
    /// The node it was mapped to.
    mesh_addr: Ipv6Addr,
    /// When no answer naming it can still be cached.
    deadline: Instant,
    /// Whether the NAT table has reported its rules gone.
    removed: bool,
    /// Read snapshots taken since that report.
    reads: u32,
}

/// `now` plus `secs` seconds, or as far ahead as an `Instant` can reach.
fn later(now: Instant, secs: u64) -> Instant {
    now.checked_add(Duration::from_secs(secs))
        .or_else(|| now.checked_add(Duration::from_secs(u64::from(u32::MAX))))
        .unwrap_or(now)
}

/// Pool size below which one LAN host naming new names can exhaust the pool:
/// the ceiling plus what the rate admits while removed addresses wait out
/// their TTL and grace period.
pub fn small_pool_threshold(ttl_secs: u64, grace_secs: u64) -> usize {
    let wait = usize::try_from(ttl_secs.saturating_add(grace_secs)).unwrap_or(usize::MAX);
    MAPPING_CEILING.saturating_add((MAPPING_RATE as usize).saturating_mul(wait))
}

/// Addresses in a pool: offsets `1..=total` from its network address, at most
/// 2^16 - 1 of them. A /128 has none, so it is refused.
pub fn pool_total(cidr: &str) -> Result<u32, PoolError> {
    let (_, prefix_len) = parse_ipv6_cidr(cidr)?;
    if prefix_len == 0 || prefix_len >= 128 {
        return Err(PoolError::InvalidPrefix);
    }
    let host_bits = 128 - prefix_len;
    // Cap at 2^16 addresses to avoid massive allocations, and skip offset 0,
    // the network address.
    let addrs: u32 = if host_bits >= 16 {
        1 << 16
    } else {
        1 << host_bits
    };
    Ok(addrs - 1)
}

/// The offset `steps` places on from `offset` round a ring of offsets
/// `1..=total`.
fn ring_step(offset: u32, steps: u64, total: u32) -> u32 {
    let total = u64::from(total);
    1 + ((u64::from(offset) - 1 + steps % total) % total) as u32
}

/// Virtual IP pool manager.
///
/// Addresses are issued in ring order from a moving cursor, so an address
/// freed in this run is reused only after the cursor has gone round the pool.
/// Positions on the ring count from the run's start offset; the durable mark
/// is the first position not yet covered by a written state, and the pool
/// does not issue at or past it while marks are enforced.
pub struct VirtualIpPool {
    /// The pool CIDR as configured.
    cidr: String,
    /// The pool's network address, host bits cleared, and prefix length.
    network: (Ipv6Addr, u8),
    /// The network address as an integer; offset `o` is `base + o`.
    base: u128,
    /// Offsets that may be issued.
    free: BTreeSet<u32>,
    /// Active mappings keyed by NodeAddr.
    mappings: HashMap<NodeAddr, VirtualIpMapping>,
    /// Reverse map: virtual IP → NodeAddr.
    reverse: HashMap<Ipv6Addr, NodeAddr>,
    /// DNS TTL / mapping TTL in seconds.
    ttl_secs: u64,
    /// Grace period after last session before reclamation.
    grace_secs: u64,
    /// Total pool size.
    total: u32,
    /// Most live mappings admitted before new names are refused.
    ceiling: usize,
    /// Rate limit on new mappings.
    bucket: Bucket,
    /// The offset at ring position 0.
    start: u32,
    /// The ring position the next new name is issued at or after.
    cursor: u64,
    /// The first position no written state covers.
    durable_mark: Option<u64>,
    /// Whether the durable mark bounds allocation.
    marks: MarkMode,
    /// Offsets held because the previous run may have answered with them.
    restart_held: BTreeSet<u32>,
    /// When the previous run's answers have all expired.
    hold_until: Option<Instant>,
    /// The latest time the pool has been given, for state written without one.
    clock: Instant,
    /// The warning for refused new names.
    refusals: RefusalLatch,
    /// Refusals at a bound since start.
    refused_total: u64,
    /// Mappings replaced at the ceiling since start.
    evicted_total: u64,
    /// Removed addresses waiting to return to `free`, by offset.
    releasing: HashMap<u32, Releasing>,
    /// Offset and reply-source pairs bound by a conntrack entry that the
    /// current mapping does not account for, with the consecutive read
    /// snapshots that have missed each. An address is not handed to a node
    /// that still has such a binding to it.
    surviving: HashMap<(u32, Ipv6Addr), u32>,
    /// Whether conntrack evidence is trusted.
    evidence: Evidence,
    /// Read snapshots taken in this run.
    reads_seen: u32,
    /// Read snapshots this run takes before a new mapping can count traffic.
    reads_needed: u32,
}

impl VirtualIpPool {
    /// Create a new pool from a CIDR string (e.g., `fd01::/112`), with the
    /// compiled-in admission limits.
    pub fn new(cidr: &str, ttl_secs: u64, grace_secs: u64) -> Result<Self, PoolError> {
        Self::with_limits(
            cidr,
            ttl_secs,
            grace_secs,
            MAPPING_CEILING,
            MAPPING_BURST,
            MAPPING_RATE,
        )
    }

    /// Create a pool with explicit admission limits.
    ///
    /// Production uses `start`; this exists so tests can set limits small
    /// enough to reach without allocating the compiled-in counts. The pool
    /// issues from the first address and keeps no state across a restart.
    pub fn with_limits(
        cidr: &str,
        ttl_secs: u64,
        grace_secs: u64,
        ceiling: usize,
        burst: u32,
        rate: u32,
    ) -> Result<Self, PoolError> {
        let (addr, prefix_len) = parse_ipv6_cidr(cidr)?;
        let total = pool_total(cidr)?;
        // The kernel routes the prefix, not the address as written, so
        // offsets count from the prefix's network address.
        let base = u128::from(addr) & (u128::MAX << (128 - prefix_len));
        let network = Ipv6Addr::from(base);
        if network != addr {
            warn!(cidr = %cidr, network = %network, "Pool CIDR has host bits set; the pool uses its network address");
        }
        info!(cidr = %cidr, addresses = total, "Virtual IP pool initialized");

        Ok(Self {
            cidr: cidr.to_string(),
            network: (network, prefix_len as u8),
            base,
            free: (1..=total).collect(),
            mappings: HashMap::new(),
            reverse: HashMap::new(),
            ttl_secs,
            grace_secs,
            total,
            ceiling,
            bucket: Bucket::new(burst, rate),
            start: 1,
            cursor: 0,
            durable_mark: None,
            marks: MarkMode::Ignored,
            restart_held: BTreeSet::new(),
            hold_until: None,
            clock: Instant::now(),
            refusals: RefusalLatch::default(),
            refused_total: 0,
            evicted_total: 0,
            releasing: HashMap::new(),
            surviving: HashMap::new(),
            evidence: Evidence {
                trusted: true,
                unread: 0,
                read: 0,
            },
            reads_seen: 0,
            reads_needed: 0,
        })
    }

    /// Create the pool the gateway runs with, from `start`, at `now`.
    ///
    /// The pool refuses new names until its first state write is confirmed
    /// or has failed. A restored pool issues from where the previous run's
    /// written stretch ends, and holds that stretch and every offset the
    /// previous run had live until any answer naming them has expired.
    pub fn start(
        cidr: &str,
        ttl_secs: u64,
        grace_secs: u64,
        start: PoolStart,
        now: Instant,
    ) -> Result<Self, PoolError> {
        let mut pool = Self::new(cidr, ttl_secs, grace_secs)?;
        pool.clock = now;
        pool.marks = MarkMode::Pending;
        // The previous run's conntrack entries outlive it, and only reads
        // tell which of them bind a free address to a node. Until enough
        // reads have been taken, one that missed an entry could let a
        // reissued address read the old entry's reply as its own traffic.
        pool.reads_needed = MAX_ABSENT_READS;
        let total = pool.total;
        match start {
            PoolStart::Fresh { offset } => pool.start = 1 + offset.saturating_sub(1) % total,
            PoolStart::Restored(state) => {
                let hold = now.checked_add(Duration::from_secs(state.hold_secs));
                let valid = state.version == 1
                    && state.total == total
                    && (1..=total).contains(&state.from)
                    && state.span <= total
                    && state
                        .held
                        .iter()
                        .all(|[a, b]| 1 <= *a && a <= b && *b <= total);
                debug_assert!(valid && hold.is_some(), "state is validated before start");
                if valid && let Some(hold) = hold {
                    pool.start = ring_step(state.from, u64::from(state.span), total);
                    let mut held: BTreeSet<u32> =
                        state.held.iter().flat_map(|[a, b]| *a..=*b).collect();
                    held.extend(
                        (0..u64::from(state.span)).map(|k| ring_step(state.from, k, total)),
                    );
                    for offset in &held {
                        pool.free.remove(offset);
                    }
                    pool.restart_held = held;
                    pool.hold_until = Some(hold);
                }
            }
        }
        Ok(pool)
    }

    /// The pool's network address and prefix length.
    pub fn network(&self) -> (Ipv6Addr, u8) {
        self.network
    }

    /// The address at `offset`.
    fn offset_addr(&self, offset: u32) -> Ipv6Addr {
        Ipv6Addr::from(self.base + u128::from(offset))
    }

    /// Whether `addr` lies inside the pool's prefix, which the gateway
    /// routes to itself.
    fn in_prefix(&self, addr: Ipv6Addr) -> bool {
        let (network, prefix_len) = self.network;
        let mask = u128::MAX << (128 - u32::from(prefix_len));
        u128::from(addr) & mask == u128::from(network)
    }

    /// The offset of `addr`, when it lies in the pool.
    fn addr_offset(&self, addr: Ipv6Addr) -> Option<u32> {
        let offset = u128::from(addr).checked_sub(self.base)?;
        u32::try_from(offset)
            .ok()
            .filter(|o| (1..=self.total).contains(o))
    }

    /// The offset at ring position `position`.
    fn offset_at(&self, position: u64) -> u32 {
        ring_step(self.start, position, self.total)
    }

    /// Positions from offset `from` forward to offset `to`, within one lap.
    fn ring_distance(&self, from: u32, to: u32) -> u64 {
        let total = u64::from(self.total);
        (u64::from(to) + total - u64::from(from)) % total
    }

    /// Free offsets in ring order from the cursor, each with its position,
    /// within one lap.
    fn free_from_cursor(&self) -> impl Iterator<Item = (u32, u64)> + '_ {
        let here = self.offset_at(self.cursor);
        self.free
            .range(here..)
            .chain(self.free.range(..here))
            .map(move |&offset| (offset, self.cursor + self.ring_distance(here, offset)))
    }

    /// Return held and removed offsets to the free set once nothing can
    /// still name them.
    ///
    /// An offset held from the previous run returns once its hold has passed
    /// and `MAX_ABSENT_READS` read snapshots have been taken in this run, so
    /// the previous run's bindings are known. A removed offset returns once
    /// its deadline has passed, the NAT table has reported its rules gone,
    /// and `MAX_ABSENT_READS` read snapshots have followed that report. While
    /// evidence is not trusted the read conditions are dropped.
    fn release_due(&mut self, now: Instant) {
        let reads_count = self.evidence.trusted;
        if self.hold_until.is_some_and(|until| now >= until)
            && (!reads_count || self.reads_seen >= MAX_ABSENT_READS)
        {
            self.free.append(&mut self.restart_held);
            self.hold_until = None;
        }
        let ready: Vec<u32> = self
            .releasing
            .iter()
            .filter(|(_, r)| {
                now >= r.deadline && r.removed && (!reads_count || r.reads >= MAX_ABSENT_READS)
            })
            .map(|(offset, _)| *offset)
            .collect();
        for offset in ready {
            self.releasing.remove(&offset);
            self.free.insert(offset);
        }
    }

    /// Track whether conntrack evidence can be trusted, from one tick's
    /// snapshot.
    fn observe_evidence(&mut self, read: bool) {
        let evidence = &mut self.evidence;
        if read {
            evidence.unread = 0;
            evidence.read = evidence.read.saturating_add(1);
            self.reads_seen = self.reads_seen.saturating_add(1);
            for releasing in self.releasing.values_mut().filter(|r| r.removed) {
                releasing.reads = releasing.reads.saturating_add(1);
            }
        } else {
            evidence.unread = evidence.unread.saturating_add(1);
            evidence.read = 0;
        }
        if evidence.trusted && evidence.unread >= MAX_UNREAD_TICKS {
            evidence.trusted = false;
            warn!(
                unread_ticks = evidence.unread,
                "Conntrack evidence lost; mappings created from now on cannot count as carrying traffic, and removed addresses return once their NAT removal is reported"
            );
        } else if !evidence.trusted && evidence.read >= MAX_ABSENT_READS {
            evidence.trusted = true;
            info!(
                read_ticks = evidence.read,
                "Conntrack evidence restored; new mappings count traffic again"
            );
        }
    }

    /// Update the bindings that old conntrack entries keep, from a read
    /// snapshot.
    fn observe_bindings(&mut self, conntrack: &ConntrackSnapshot) {
        let mut seen = HashSet::new();
        for (dst, sources) in &conntrack.bindings {
            let Some(offset) = self.addr_offset(*dst) else {
                continue;
            };
            let current = self
                .reverse
                .get(dst)
                .and_then(|node| self.mappings.get(node))
                .map(|m| m.mesh_addr);
            for src in sources {
                if src != dst && current != Some(*src) {
                    seen.insert((offset, *src));
                }
            }
        }
        self.surviving.retain(|pair, misses| {
            *misses += 1;
            seen.contains(pair) || *misses < MAX_ABSENT_READS
        });
        for pair in seen {
            self.surviving.insert(pair, 0);
        }
    }

    /// Tell the pool whether a conntrack source can be read, as found at
    /// start. Without one, no mapping created from then on counts as
    /// carrying traffic and nothing waits for reads, until
    /// `MAX_ABSENT_READS` consecutive ticks have read a snapshot, as after
    /// any loss of evidence.
    pub fn set_evidence(&mut self, available: bool) {
        self.evidence.trusted = available;
        self.evidence.read = 0;
    }

    /// Remove a never-used mapping to make room at the ceiling.
    fn evict(&mut self, node_addr: NodeAddr) -> Option<Evicted> {
        let mapping = self.mappings.remove(&node_addr)?;
        self.reverse.remove(&mapping.virtual_ip);
        self.evicted_total += 1;
        self.start_releasing(&mapping);
        debug!(
            virtual_ip = %mapping.virtual_ip,
            mesh_addr = %mapping.mesh_addr,
            "Evicted never-used mapping"
        );
        Some(Evicted {
            virtual_ip: mapping.virtual_ip,
            mesh_addr: mapping.mesh_addr,
        })
    }

    /// Hold a removed mapping's address until no answer can still name it.
    ///
    /// An answer given at creation can be cached until `answer_deadline`,
    /// and one given later (TTL 0 for a never-used mapping kept by traffic)
    /// is allowed the grace period, as every answer was before.
    fn start_releasing(&mut self, mapping: &VirtualIpMapping) {
        let Some(offset) = self.addr_offset(mapping.virtual_ip) else {
            return;
        };
        let deadline = mapping
            .answer_deadline
            .max(later(mapping.last_answer, self.grace_secs));
        self.releasing.insert(
            offset,
            Releasing {
                mesh_addr: mapping.mesh_addr,
                deadline,
                removed: false,
                reads: 0,
            },
        );
    }

    /// The TTL to answer `mapping` with at `now`: the configured TTL for a
    /// mapping that has carried traffic, and otherwise no more than what is
    /// left until TTL after its creation, so a re-query cannot extend it.
    fn answer_ttl(&self, mapping: &VirtualIpMapping, now: Instant) -> u32 {
        let ttl = if mapping.used {
            self.ttl_secs
        } else {
            later(mapping.created, self.ttl_secs)
                .saturating_duration_since(now)
                .as_secs()
                .min(self.ttl_secs)
        };
        u32::try_from(ttl).unwrap_or(u32::MAX)
    }

    /// Offsets a client may still hold an answer for, as sorted inclusive
    /// ranges: every mapped offset and every offset held from the previous
    /// run.
    fn held_ranges(&self) -> Vec<[u32; 2]> {
        let mut held: BTreeSet<u32> = self
            .reverse
            .keys()
            .filter_map(|addr| self.addr_offset(*addr))
            .collect();
        held.extend(self.restart_held.iter().copied());
        held.extend(self.releasing.keys().copied());
        let mut ranges: Vec<[u32; 2]> = Vec::new();
        for offset in held {
            match ranges.last_mut() {
                Some([_, end]) if *end + 1 == offset => *end = offset,
                _ => ranges.push([offset, offset]),
            }
        }
        ranges
    }

    /// How long a client may hold an answer naming a held offset.
    fn hold_secs(&self) -> u64 {
        let restart = self.hold_until.map_or(0, |until| {
            until
                .saturating_duration_since(self.clock)
                .as_secs()
                .saturating_add(1)
        });
        self.ttl_secs.saturating_add(self.grace_secs).max(restart)
    }

    /// The state the pool would write, with the cursor's offset and `span`.
    fn state(&self, span: u32) -> PoolState {
        PoolState {
            version: 1,
            pool: self.cidr.clone(),
            total: self.total,
            from: self.offset_at(self.cursor),
            span,
            held: self.held_ranges(),
            hold_secs: self.hold_secs(),
        }
    }

    /// The state to write before issuing further, if one is due.
    ///
    /// One is due when no mark is durable yet, or fewer than
    /// `MARK_LOW_WATER` free offsets lie between the cursor and the durable
    /// mark. The new mark lies just past the `MARK_RESERVE`-th free offset
    /// ahead of the cursor, or past the last free one within a lap.
    pub fn mark_request(&self) -> Option<PoolState> {
        if let Some(mark) = self.durable_mark {
            let ahead = self
                .free_from_cursor()
                .take_while(|&(_, position)| position < mark)
                .take(MARK_LOW_WATER as usize)
                .count();
            if ahead >= MARK_LOW_WATER as usize {
                return None;
            }
        }
        let mark = self
            .free_from_cursor()
            .take(MARK_RESERVE as usize)
            .last()
            .map_or(self.cursor, |(_, position)| position + 1);
        let span = u32::try_from(mark - self.cursor).unwrap_or(self.total);
        Some(self.state(span.min(self.total)))
    }

    /// The state to write when the gateway stops cleanly, after nothing can
    /// be issued any more: no stretch, only the offsets a client may still
    /// hold an answer for.
    pub fn shutdown_state(&self) -> PoolState {
        self.state(0)
    }

    /// The state that carries a restored pool's holds to the next start, for
    /// a start that ends before its first write: the offsets it holds, with
    /// no stretch, for the hold that remains. `None` for a pool that holds
    /// nothing from a previous run.
    pub fn carry_state(&self) -> Option<PoolState> {
        let until = self.hold_until?;
        let mut state = self.state(0);
        state.hold_secs = until
            .saturating_duration_since(self.clock)
            .as_secs()
            .saturating_add(1);
        Some(state)
    }

    /// Record that `state`, taken from `mark_request`, was written.
    pub fn confirm_mark(&mut self, state: &PoolState) {
        let here = self.offset_at(self.cursor);
        let from = self
            .cursor
            .saturating_sub(self.ring_distance(state.from, here));
        let mark = from + u64::from(state.span);
        self.durable_mark = Some(self.durable_mark.map_or(mark, |old| old.max(mark)));
        self.marks = MarkMode::Enforced;
    }

    /// Record that the state could not be written: issue without marks
    /// until a later write is confirmed.
    pub fn mark_failed(&mut self) {
        self.marks = MarkMode::Ignored;
    }

    /// Count a refusal at one of the pool's bounds, warning on the first of
    /// an episode.
    fn refuse(&mut self, error: PoolError, now: Instant) -> PoolError {
        self.refused_total += 1;
        if self.refusals.refuse(now) {
            let bound = match &error {
                PoolError::AtCeiling(_) => self.ceiling as u64,
                PoolError::Exhausted(_) => u64::from(self.total),
                PoolError::AwaitingMark => self
                    .durable_mark
                    .map_or(0, |mark| u64::from(self.offset_at(mark))),
                _ => 0,
            };
            warn!(
                reason = error.reason(),
                bound,
                error = %error,
                "Pool refusing new names"
            );
        }
        error
    }

    /// Record that the NAT table no longer translates `virtual_ip` to
    /// `mesh_addr`.
    pub fn nat_removed(&mut self, virtual_ip: Ipv6Addr, mesh_addr: Ipv6Addr) {
        if let Some(offset) = self.addr_offset(virtual_ip)
            && let Some(releasing) = self.releasing.get_mut(&offset)
            && releasing.mesh_addr == mesh_addr
            && !releasing.removed
        {
            releasing.removed = true;
            releasing.reads = 0;
        }
    }

    /// Refresh an existing mapping's TTL clock, never creating one.
    ///
    /// Returns whether a mapping for `node_addr` was refreshed. Only a
    /// mapping that has carried traffic is: a name nobody has used expires
    /// TTL plus grace after it was created however often it is queried.
    /// Refreshing a draining mapping cancels reclamation for the renewed TTL.
    pub fn refresh_if_present(&mut self, node_addr: NodeAddr) -> bool {
        self.refresh_at(node_addr, Instant::now())
    }

    fn refresh_at(&mut self, node_addr: NodeAddr, now: Instant) -> bool {
        match self.mappings.get_mut(&node_addr) {
            Some(mapping) if mapping.used => {
                mapping.last_referenced = now;
                if mapping.state == MappingState::Draining {
                    mapping.state = MappingState::Allocated;
                    mapping.drain_start = None;
                }
                true
            }
            _ => false,
        }
    }

    /// Allocate a virtual IP for the given node. Idempotent: returns
    /// existing mapping if one exists.
    pub fn allocate(
        &mut self,
        node_addr: NodeAddr,
        mesh_addr: Ipv6Addr,
        dns_name: &str,
    ) -> Result<Allocation, PoolError> {
        self.allocate_at(node_addr, mesh_addr, dns_name, Instant::now())
    }

    /// `allocate` at a given instant, which drives the rate limit's refill
    /// and stamps a new or refreshed mapping.
    ///
    /// An existing mapping is returned before either limit is consulted, so a
    /// name already in use keeps resolving when new names are refused. At the
    /// ceiling a new name replaces the oldest mapping that has never carried
    /// traffic, and is refused only when every mapping has. Nothing is
    /// replaced unless the new name gets an address and a token. A mesh
    /// address inside the pool's prefix is refused.
    pub fn allocate_at(
        &mut self,
        node_addr: NodeAddr,
        mesh_addr: Ipv6Addr,
        dns_name: &str,
        now: Instant,
    ) -> Result<Allocation, PoolError> {
        // The gateway routes the whole pool prefix to itself, so traffic to a
        // mesh address inside it never reaches the mesh, and the gateway's
        // own replies from that address would read as the mapping's traffic.
        if self.in_prefix(mesh_addr) {
            return Err(PoolError::InsidePool(mesh_addr));
        }
        self.clock = self.clock.max(now);
        self.release_due(now);

        // Idempotent: return the existing mapping, refreshed if it has
        // carried traffic.
        self.refresh_at(node_addr, now);
        if let Some(mapping) = self.mappings.get_mut(&node_addr) {
            mapping.last_answer = now;
            let mapping = &self.mappings[&node_addr];
            return Ok(Allocation {
                virtual_ip: mapping.virtual_ip,
                is_new: false,
                ttl: self.answer_ttl(mapping, now),
                evicted: None,
            });
        }

        // Ceiling first, so a refusal there costs no token and names the
        // ceiling whatever the bucket holds.
        let victim = if self.mappings.len() >= self.ceiling {
            let oldest = self
                .mappings
                .values()
                .filter(|m| !m.used)
                .min_by_key(|m| (m.created, m.virtual_ip))
                .map(|m| m.node_addr);
            match oldest {
                Some(node) => Some(node),
                None => return Err(self.refuse(PoolError::AtCeiling(self.mappings.len()), now)),
            }
        } else {
            None
        };
        self.bucket.refill(now);
        if !self.bucket.has_token() {
            return Err(PoolError::RateLimited);
        }
        if self.marks == MarkMode::Pending {
            return Err(self.refuse(PoolError::AwaitingMark, now));
        }
        // Skip an address that a surviving conntrack entry still binds to
        // this node: its old entry would read as the new mapping's traffic.
        let found = self
            .free_from_cursor()
            .find(|(offset, _)| !self.surviving.contains_key(&(*offset, mesh_addr)));
        let Some((offset, position)) = found else {
            return Err(self.refuse(PoolError::Exhausted(self.mappings.len()), now));
        };
        if self.marks == MarkMode::Enforced
            && self.durable_mark.is_some_and(|mark| position >= mark)
        {
            return Err(self.refuse(PoolError::AwaitingMark, now));
        }
        let evicted = victim.and_then(|node| self.evict(node));
        self.bucket.take();
        self.free.remove(&offset);
        self.cursor = position + 1;
        let virtual_ip = self.offset_addr(offset);

        let mapping = VirtualIpMapping {
            node_addr,
            virtual_ip,
            mesh_addr,
            dns_name: dns_name.to_string(),
            state: MappingState::Allocated,
            created: now,
            last_referenced: now,
            drain_start: None,
            session_count: 0,
            used: false,
            blind: !self.evidence.trusted || self.reads_seen < self.reads_needed,
            answer_deadline: later(now, self.ttl_secs.saturating_add(self.grace_secs)),
            last_answer: now,
        };

        self.mappings.insert(node_addr, mapping);
        self.reverse.insert(virtual_ip, node_addr);

        info!(
            virtual_ip = %virtual_ip,
            mesh_addr = %mesh_addr,
            dns_name = %dns_name,
            "Allocated virtual IP"
        );

        Ok(Allocation {
            virtual_ip,
            is_new: true,
            ttl: u32::try_from(self.ttl_secs).unwrap_or(u32::MAX),
            evicted,
        })
    }

    /// Periodic tick — drives state transitions. Returns events for
    /// the NAT and network modules.
    pub fn tick(&mut self, now: Instant, conntrack: &ConntrackSnapshot) -> Vec<PoolEvent> {
        self.clock = self.clock.max(now);
        self.observe_evidence(conntrack.read);
        if conntrack.read {
            self.observe_bindings(conntrack);
        }
        // Before this tick's own frees, so an address freed now cannot
        // leave in the same tick.
        self.release_due(now);
        if let Some(refused) = self.refusals.release(now) {
            info!(refused, "Pool accepting new names again");
        }
        let mut events = Vec::new();
        let mut to_free = Vec::new();
        let ttl = std::time::Duration::from_secs(self.ttl_secs);
        let grace = std::time::Duration::from_secs(self.grace_secs);
        let trusted = self.evidence.trusted;

        for (node_addr, mapping) in &mut self.mappings {
            // One map lookup: the conntrack table was read once, before the
            // pool lock was taken.
            let sessions = conntrack.sessions_for(mapping.virtual_ip);
            mapping.session_count = sessions;

            // Only a reply from the mapped node counts as use: not a reply
            // from the virtual IP itself (an unmapped pool address is a
            // local address of the gateway), and not one from an earlier
            // holder of the address.
            if trusted
                && !mapping.used
                && !mapping.blind
                && conntrack.replied_from(mapping.virtual_ip, mapping.mesh_addr)
            {
                mapping.used = true;
                debug!(virtual_ip = %mapping.virtual_ip, "Mapping carried traffic");
            }

            // Live data-plane traffic pins the mapping: refresh the TTL
            // clock whenever conntrack reports active sessions, so an
            // in-use mapping never ages out from under the client.
            if sessions > 0 {
                mapping.last_referenced = now;
            }

            match mapping.state {
                MappingState::Allocated => {
                    if sessions > 0 {
                        mapping.state = MappingState::Active;
                        debug!(
                            virtual_ip = %mapping.virtual_ip,
                            sessions,
                            "Mapping activated"
                        );
                    } else if now.duration_since(mapping.last_referenced) > ttl {
                        // TTL expired — enter draining with grace period so
                        // the mapping survives browser DNS cache, even if no
                        // conntrack sessions were observed (short HTTP requests
                        // may complete between ticks).
                        mapping.state = MappingState::Draining;
                        mapping.drain_start = Some(now);
                        debug!(
                            virtual_ip = %mapping.virtual_ip,
                            "Allocated mapping TTL expired, draining"
                        );
                    }
                }
                MappingState::Active => {
                    // The traffic refresh above keeps last_referenced == now
                    // while sessions > 0, so the TTL can only trip once the
                    // mapping is idle (no conntrack sessions). An actively used
                    // mapping never drains; an idle one enters the grace period.
                    if now.duration_since(mapping.last_referenced) > ttl {
                        mapping.state = MappingState::Draining;
                        mapping.drain_start = Some(now);
                    }
                }
                MappingState::Draining => {
                    if sessions > 0 {
                        // Traffic resumed before reclamation: recover to
                        // Active and clear drain_start so the next drain
                        // gets a fresh grace window rather than reusing a
                        // stale one.
                        mapping.state = MappingState::Active;
                        mapping.drain_start = None;
                        debug!(
                            virtual_ip = %mapping.virtual_ip,
                            sessions,
                            "Draining mapping recovered to active (traffic resumed)"
                        );
                    } else if let Some(drain_start) = mapping.drain_start
                        && now.duration_since(drain_start) > grace
                    {
                        to_free.push(*node_addr);
                    }
                }
            }
        }

        // Free expired mappings. Each address waits in `releasing` until no
        // answer or conntrack entry can still name it.
        for node_addr in to_free {
            if let Some(mapping) = self.mappings.remove(&node_addr) {
                self.reverse.remove(&mapping.virtual_ip);
                self.start_releasing(&mapping);
                info!(
                    virtual_ip = %mapping.virtual_ip,
                    mesh_addr = %mapping.mesh_addr,
                    "Reclaimed virtual IP"
                );
                events.push(PoolEvent::MappingRemoved {
                    virtual_ip: mapping.virtual_ip,
                    mesh_addr: mapping.mesh_addr,
                });
            }
        }

        events
    }

    /// Pool utilization summary.
    pub fn status(&self) -> PoolStatus {
        let mut allocated = 0;
        let mut active = 0;
        let mut draining = 0;
        for mapping in self.mappings.values() {
            match mapping.state {
                MappingState::Allocated => allocated += 1,
                MappingState::Active => active += 1,
                MappingState::Draining => draining += 1,
            }
        }
        PoolStatus {
            total: self.total as usize,
            allocated,
            active,
            draining,
            free: self.free.len(),
            evicted: self.evicted_total,
            releasing: self.releasing.len() + self.restart_held.len(),
            refused: self.refused_total,
        }
    }

    /// Summary of all active mappings.
    pub fn mapping_info(&self, now: Instant) -> Vec<MappingInfo> {
        self.mappings
            .values()
            .map(|m| MappingInfo {
                virtual_ip: m.virtual_ip,
                mesh_addr: m.mesh_addr,
                node_addr: m.node_addr,
                dns_name: m.dns_name.clone(),
                state: m.state,
                session_count: m.session_count,
                age_secs: now.duration_since(m.created).as_secs(),
                last_ref_secs: now.duration_since(m.last_referenced).as_secs(),
                used: m.used,
            })
            .collect()
    }

    /// Look up which node a virtual IP maps to.
    pub fn lookup_virtual_ip(&self, virtual_ip: &Ipv6Addr) -> Option<&VirtualIpMapping> {
        self.reverse
            .get(virtual_ip)
            .and_then(|addr| self.mappings.get(addr))
    }
}

/// Parse an IPv6 CIDR string into base address and prefix length.
fn parse_ipv6_cidr(cidr: &str) -> Result<(Ipv6Addr, u32), PoolError> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(PoolError::InvalidCidr(cidr.to_string()));
    }
    let addr: Ipv6Addr = parts[0]
        .parse()
        .map_err(|_| PoolError::InvalidCidr(cidr.to_string()))?;
    let prefix: u32 = parts[1]
        .parse()
        .map_err(|_| PoolError::InvalidCidr(cidr.to_string()))?;
    Ok((addr, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn pool_error_reasons_are_the_kebab_case_log_values() {
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        let cases = [
            (PoolError::AtCeiling(1), "ceiling"),
            (PoolError::RateLimited, "rate-limited"),
            (PoolError::Exhausted(1), "exhausted"),
            (PoolError::AwaitingMark, "awaiting-mark"),
            (PoolError::InsidePool(addr), "inside-pool"),
            (PoolError::InvalidCidr(String::new()), "invalid"),
            (PoolError::InvalidPrefix, "invalid"),
        ];
        for (error, reason) in cases {
            assert_eq!(error.reason(), reason, "{error:?}");
        }
    }

    /// Session counts a test sets directly, handed to `tick` as the snapshot
    /// the tick task would have read from conntrack.
    #[derive(Default)]
    struct Sessions {
        counts: HashMap<Ipv6Addr, u32>,
        /// Entries by original destination and reply source, and whether
        /// each has seen a reply.
        bindings: Vec<(Ipv6Addr, Ipv6Addr, bool)>,
    }

    impl Sessions {
        fn new() -> Self {
            Self::default()
        }

        fn set(&mut self, addr: Ipv6Addr, count: u32) {
            self.counts.insert(addr, count);
        }

        /// An entry to `orig_dst` whose reply tuple comes from `reply_src`.
        fn bind(&mut self, orig_dst: Ipv6Addr, reply_src: Ipv6Addr, replied: bool) {
            self.bindings.push((orig_dst, reply_src, replied));
        }

        /// A read snapshot of what this holds.
        fn snapshot(&self) -> ConntrackSnapshot {
            let mut snapshot = ConntrackSnapshot::from_counts(self.counts.clone());
            for (orig_dst, reply_src, replied) in &self.bindings {
                snapshot.record_binding(*orig_dst, *reply_src, *replied);
            }
            snapshot
        }
    }

    /// Mark the mapping for node `i` used, as a reply from its mesh address
    /// read on a tick at `now` would.
    fn mark_used(pool: &mut VirtualIpPool, i: u8, now: Instant) {
        let vip = pool.mappings[&make_node_addr(i)].virtual_ip;
        let mut replies = Sessions::new();
        replies.bind(vip, make_mesh_addr(i), true);
        pool.tick(now, &replies.snapshot());
        assert!(
            pool.mappings[&make_node_addr(i)].used,
            "control: marked used"
        );
    }

    /// An allocation's address and whether it was new.
    fn pair(allocation: Allocation) -> (Ipv6Addr, bool) {
        (allocation.virtual_ip, allocation.is_new)
    }

    fn make_node_addr(byte: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = byte;
        NodeAddr::from_bytes(bytes)
    }

    fn make_mesh_addr(byte: u8) -> Ipv6Addr {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xfd;
        bytes[15] = byte;
        Ipv6Addr::from(bytes)
    }

    #[test]
    fn test_parse_cidr() {
        let (addr, prefix) = parse_ipv6_cidr("fd01::/112").unwrap();
        assert_eq!(addr, "fd01::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(prefix, 112);
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert!(parse_ipv6_cidr("not-a-cidr").is_err());
        assert!(parse_ipv6_cidr("fd01::").is_err());
        assert!(parse_ipv6_cidr("fd01::/abc").is_err());
    }

    #[test]
    fn a_pool_cidr_with_host_bits_set_issues_only_addresses_inside_its_prefix() {
        let pool = VirtualIpPool::with_limits("fd01::1/112", 60, 60, 10, 10, 10).unwrap();
        let network: Ipv6Addr = "fd01::".parse().unwrap();
        assert_eq!(
            pool.network(),
            (network, 112),
            "the pool's network is the configured address, not its prefix"
        );
        let mask = u128::MAX << 16;
        for offset in [1, pool.total] {
            let addr = pool.offset_addr(offset);
            assert_eq!(
                u128::from(addr) & mask,
                u128::from(network),
                "offset {offset} gives {addr}, outside fd01::/112"
            );
        }
    }

    #[test]
    fn a_pool_with_no_addresses_is_refused_at_start() {
        assert!(
            matches!(pool_total("fd01::1/128"), Err(PoolError::InvalidPrefix)),
            "a /128 pool, which has no address to issue, was accepted"
        );
        let start = PoolStart::Fresh { offset: 1 };
        assert!(VirtualIpPool::start("fd01::1/128", 60, 60, start, Instant::now()).is_err());
        assert_eq!(
            pool_total("fd01::/127").unwrap(),
            1,
            "a /127 has one address"
        );
    }

    #[test]
    fn test_pool_creation() {
        let pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
        // /120 = 8 host bits = 256 addresses, minus 1 (network) = 255
        assert_eq!(pool.total, 255);
        assert_eq!(pool.free.len(), 255);
    }

    #[test]
    fn test_pool_allocation() {
        let mut pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);

        let (vip, is_new) = pair(pool.allocate(node, mesh, "test.fips").unwrap());
        assert!(is_new);
        assert_eq!(vip, "fd01::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(pool.free.len(), 254);
    }

    #[test]
    fn test_pool_idempotent() {
        let mut pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);

        let (vip1, new1) = pair(pool.allocate(node, mesh, "test.fips").unwrap());
        let (vip2, new2) = pair(pool.allocate(node, mesh, "test.fips").unwrap());
        assert!(new1);
        assert!(!new2);
        assert_eq!(vip1, vip2);
        assert_eq!(pool.free.len(), 254);
    }

    #[test]
    fn test_pool_exhaustion() {
        // /126 = 2 host bits = 4 addresses, minus 1 = 3
        let mut pool = VirtualIpPool::new("fd01::/126", 60, 60).unwrap();
        assert_eq!(pool.total, 3);

        for i in 1..=3u8 {
            pool.allocate(make_node_addr(i), make_mesh_addr(i), "test.fips")
                .unwrap();
        }
        assert!(
            pool.allocate(make_node_addr(4), make_mesh_addr(4), "test.fips")
                .is_err()
        );
    }

    /// A `/120` pool with the given limits, TTL and grace of 60 s.
    fn limited_pool(ceiling: usize, burst: u32, rate: u32) -> VirtualIpPool {
        VirtualIpPool::with_limits("fd01::/120", 60, 60, ceiling, burst, rate).unwrap()
    }

    /// Allocate node `i` at `now`.
    fn alloc(pool: &mut VirtualIpPool, i: u8, now: Instant) -> Result<(Ipv6Addr, bool), PoolError> {
        pool.allocate_at(make_node_addr(i), make_mesh_addr(i), "test.fips", now)
            .map(pair)
    }

    #[test]
    fn ceiling_refuses_only_when_every_mapping_has_carried_traffic() {
        let t0 = Instant::now();
        let mut pool = limited_pool(4, 10, 1);
        let mut vips = Vec::new();
        for i in 1..=4u8 {
            vips.push(alloc(&mut pool, i, t0).unwrap().0);
        }
        for i in 1..=4u8 {
            mark_used(&mut pool, i, t0);
        }
        assert_eq!(pool.bucket.tokens(), 6);

        assert!(
            matches!(alloc(&mut pool, 5, t0), Err(PoolError::AtCeiling(4))),
            "a fifth new name must be refused when every mapping carries traffic"
        );
        assert_eq!(
            pool.bucket.tokens(),
            6,
            "a ceiling refusal must not take a token"
        );
        assert_eq!(
            alloc(&mut pool, 2, t0).unwrap(),
            (vips[1], false),
            "a name that already has a mapping must still resolve at the ceiling"
        );
    }

    #[test]
    fn ceiling_is_checked_before_the_rate_limit() {
        let t0 = Instant::now();
        // The bucket empties exactly as the ceiling is reached, and every
        // mapping carries traffic, so none can be replaced.
        let mut pool = limited_pool(3, 3, 1);
        for i in 1..=3u8 {
            alloc(&mut pool, i, t0).unwrap();
            mark_used(&mut pool, i, t0);
        }
        assert_eq!(pool.bucket.tokens(), 0);
        assert!(
            matches!(alloc(&mut pool, 4, t0), Err(PoolError::AtCeiling(3))),
            "a name refused at the ceiling must report the ceiling, not the rate"
        );
    }

    #[test]
    fn rate_limit_refuses_a_burst_keeps_existing_names_and_refills() {
        let t0 = Instant::now();
        let mut pool = limited_pool(100, 2, 1);
        let (vip1, _) = alloc(&mut pool, 1, t0).unwrap();
        alloc(&mut pool, 2, t0).unwrap();
        assert!(
            matches!(alloc(&mut pool, 3, t0), Err(PoolError::RateLimited)),
            "a third new name at the same instant must be refused by a burst of 2"
        );

        assert_eq!(
            alloc(&mut pool, 1, t0).unwrap(),
            (vip1, false),
            "an existing name must resolve with the bucket empty"
        );
        assert_eq!(pool.bucket.tokens(), 0);
        assert!(
            matches!(alloc(&mut pool, 3, t0), Err(PoolError::RateLimited)),
            "resolving an existing name must not have freed a token"
        );

        let (_, is_new) = alloc(&mut pool, 3, t0 + Duration::from_secs(1)).unwrap();
        assert!(is_new, "one refill interval later a new name must allocate");
    }

    #[test]
    fn exhausted_pool_takes_no_token() {
        let t0 = Instant::now();
        // /126 = 3 usable addresses.
        let mut pool = VirtualIpPool::with_limits("fd01::/126", 60, 60, 100, 10, 1).unwrap();
        for i in 1..=3u8 {
            alloc(&mut pool, i, t0).unwrap();
        }
        assert!(matches!(
            alloc(&mut pool, 4, t0),
            Err(PoolError::Exhausted(3))
        ));
        assert_eq!(
            pool.bucket.tokens(),
            7,
            "a refusal for an exhausted pool must not take a token"
        );
    }

    /// A node address for index `i`, for tests that need more than 255.
    fn node_n(i: u32) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = 0x01;
        bytes[12..].copy_from_slice(&i.to_be_bytes());
        NodeAddr::from_bytes(bytes)
    }

    /// The mesh address for index `i`.
    fn mesh_n(i: u32) -> Ipv6Addr {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xfd;
        bytes[1] = 0x9a;
        bytes[12..].copy_from_slice(&i.to_be_bytes());
        Ipv6Addr::from(bytes)
    }

    #[test]
    fn a_restored_pool_does_not_reissue_the_previous_runs_addresses() {
        let t0 = Instant::now();
        let mut first =
            VirtualIpPool::start("fd01::/112", 60, 60, PoolStart::Fresh { offset: 1 }, t0).unwrap();
        // The start write, then three names in the stretch it covers, then a
        // crash: nothing more is written.
        let state = first
            .mark_request()
            .expect("a fresh pool has no durable mark, so it asks for one");
        first.confirm_mark(&state);
        let issued: Vec<Ipv6Addr> = (1..=3u8)
            .map(|i| alloc(&mut first, i, t0).expect("the first run allocates").0)
            .collect();

        let t1 = t0 + Duration::from_secs(1);
        let mut second =
            VirtualIpPool::start("fd01::/112", 60, 60, PoolStart::Restored(state), t1).unwrap();
        let mark = second
            .mark_request()
            .expect("a restored pool has no durable mark yet");
        second.confirm_mark(&mark);
        let next = alloc(&mut second, 4, t1);
        assert!(
            next.is_ok(),
            "the restored pool refused a new name: {next:?}"
        );
        let (address, _) = next.unwrap();
        assert!(
            !issued.contains(&address),
            "the restored pool gave a new name {address}, which the previous run \
             issued as one of {issued:?}; a client's cached answer for it now \
             reaches a different node"
        );
    }

    /// A pool driven the way the gateway drives it: ticks every 10 s with a
    /// read snapshot that pins the addresses in `pinned`, NAT removals
    /// reported for every removed mapping, and every requested state written
    /// and confirmed.
    struct Sim {
        pool: VirtualIpPool,
        now: Instant,
        next_tick: Instant,
        pinned: Sessions,
        /// The last state written, as a crash would leave it.
        written: Option<PoolState>,
    }

    impl Sim {
        fn started(cidr: &str, ttl: u64, grace: u64, start: PoolStart, now: Instant) -> Sim {
            let mut pool = VirtualIpPool::start(cidr, ttl, grace, start, now).unwrap();
            let state = pool
                .mark_request()
                .expect("a started pool asks for a write");
            pool.confirm_mark(&state);
            Sim {
                pool,
                now,
                next_tick: now + Duration::from_secs(10),
                pinned: Sessions::new(),
                written: Some(state),
            }
        }

        /// Move time on, ticking at every 10 s boundary passed.
        fn advance(&mut self, by: Duration) {
            let until = self.now + by;
            while self.next_tick <= until {
                self.now = self.next_tick;
                self.tick();
                self.next_tick += Duration::from_secs(10);
            }
            self.now = until;
        }

        fn tick(&mut self) {
            for event in self.pool.tick(self.now, &self.pinned.snapshot()) {
                if let PoolEvent::MappingRemoved {
                    virtual_ip,
                    mesh_addr,
                } = event
                {
                    self.pool.nat_removed(virtual_ip, mesh_addr);
                }
            }
            if let Some(state) = self.pool.mark_request() {
                self.pool.confirm_mark(&state);
                self.written = Some(state);
            }
        }

        /// Allocate name `i` now.
        fn alloc(&mut self, i: u32) -> Result<Allocation, PoolError> {
            let allocation = self
                .pool
                .allocate_at(node_n(i), mesh_n(i), "test.fips", self.now)?;
            if let Some(evicted) = allocation.evicted {
                self.pool.nat_removed(evicted.virtual_ip, evicted.mesh_addr);
            }
            Ok(allocation)
        }

        /// Allocate name `i`, waiting out the rate limit and the mark.
        fn alloc_waiting(&mut self, i: u32) -> Allocation {
            for _ in 0..1000 {
                match self.alloc(i) {
                    Ok(allocation) => return allocation,
                    Err(PoolError::RateLimited | PoolError::AwaitingMark) => {
                        self.advance(Duration::from_millis(100))
                    }
                    Err(e) => panic!("name {i} refused: {e}"),
                }
            }
            panic!("name {i} still refused after 100 s");
        }

        /// The offset of `addr` in this pool.
        fn offset(&self, addr: Ipv6Addr) -> u32 {
            self.pool.addr_offset(addr).expect("a pool address")
        }
    }

    #[test]
    fn a_restored_pool_holds_a_live_mapping_from_before_the_last_lap() {
        let t0 = Instant::now();
        let mut a = Sim::started("fd01::/120", 5, 5, PoolStart::Fresh { offset: 1 }, t0);
        let n1 = a.alloc_waiting(1).virtual_ip;
        a.pinned.set(n1, 1);
        let n1_offset = a.offset(n1);

        // New names, one a second, each left to expire, until the cursor has
        // gone round and stands just behind n1. At that pace about 60
        // addresses are mapped or waiting for release at once, so most of the
        // pool is free at the restart.
        let mut i = 2;
        loop {
            let allocation = a.alloc_waiting(i);
            a.advance(Duration::from_secs(1));
            i += 1;
            if a.offset(allocation.virtual_ip) == a.pool.total
                && a.pool.offset_at(a.pool.cursor) == n1_offset
            {
                break;
            }
            assert!(i < 2000, "control: the cursor did not lap");
        }
        assert!(i > 255, "control: the cursor lapped the pool");
        assert_eq!(
            a.pool.lookup_virtual_ip(&n1).map(|m| m.node_addr),
            Some(node_n(1)),
            "control: n1 is still mapped"
        );

        let state = a.pool.shutdown_state();
        let t1 = a.now + Duration::from_secs(1);
        let mut b = Sim::started("fd01::/120", 5, 5, PoolStart::Restored(state.clone()), t1);
        for k in 0..20 {
            let allocation = b.alloc(10_000 + k);
            assert!(
                allocation.is_ok(),
                "the restored pool refused: {allocation:?}"
            );
            assert_ne!(
                allocation.unwrap().virtual_ip,
                n1,
                "a live address from before the last lap was reissued after a restart"
            );
        }

        // After the hold and the reads, n1's offset can be issued again.
        b.advance(Duration::from_secs(
            state.hold_secs + 10 * u64::from(MAX_ABSENT_READS),
        ));
        assert!(b.pool.free.contains(&n1_offset), "n1's offset is released");
    }

    #[test]
    fn a_restored_slash_112_pool_holds_a_live_mapping_just_past_the_reserve() {
        // At MAPPING_RATE new names a second, a name lives at most TTL plus
        // grace (30 s) plus one tick (10 s), so at most MAPPING_BURST +
        // 10 * 40 = 450 mappings are live at once, below MAPPING_CEILING: no
        // name is ever evicted. The hold, 30 s, lets the restored pool issue
        // MAPPING_BURST + 10 * 30 = 350 names, more than the 214 offsets at
        // most between two written marks.
        let (ttl, grace) = (5, 25);
        let t0 = Instant::now();
        let mut a = Sim::started("fd01::/112", ttl, grace, PoolStart::Fresh { offset: 1 }, t0);
        let n1 = a.alloc_waiting(1).virtual_ip;
        a.pinned.set(n1, 1);
        let n1_offset = a.offset(n1);
        let total = u64::from(a.pool.total);

        // Lap until a written state's stretch ends at or before n1's
        // position on the second lap, with n1 just past it.
        let mut i = 2;
        let state = loop {
            a.alloc_waiting(i);
            i += 1;
            assert!(
                u64::from(i) < 2 * total,
                "control: no state ended just short of n1"
            );
            let Some(state) = a.written.clone() else {
                continue;
            };
            if a.pool.cursor < total {
                continue;
            }
            let end = (u64::from(state.from) - 1 + u64::from(state.span)) % total + 1;
            let gap = (u64::from(n1_offset) + total - end) % total;
            if state.span == MARK_RESERVE && gap < 300 && end != u64::from(n1_offset) + 1 {
                break state;
            }
        };
        assert_eq!(
            a.pool.lookup_virtual_ip(&n1).map(|m| m.node_addr),
            Some(node_n(1)),
            "control: n1 is still mapped"
        );

        // A crash right after that write: the next run starts from it.
        let t1 = a.now + Duration::from_secs(1);
        let mut b = Sim::started(
            "fd01::/112",
            ttl,
            grace,
            PoolStart::Restored(state.clone()),
            t1,
        );
        let hold_ends = t1 + Duration::from_secs(state.hold_secs);
        // n1's position on the restored pool's ring: it lies just past the
        // written stretch, so the pool reaches it within the hold.
        let n1_position = b.pool.ring_distance(b.pool.start, n1_offset);
        assert!(n1_position < 300, "control: n1 lies just past the stretch");
        let mut k = 0;
        while b.pool.cursor <= n1_position {
            let allocation = b.alloc_waiting(100_000 + k);
            k += 1;
            assert!(
                b.now < hold_ends,
                "control: the restored pool passed n1 within the hold"
            );
            assert_ne!(
                allocation.virtual_ip, n1,
                "a live address just past the written stretch was reissued after a crash"
            );
        }
        assert!(k > 0, "control: the restored pool issued names");
    }

    #[test]
    fn a_full_lap_stretch_survives_a_restart() {
        let t0 = Instant::now();
        let mut a = Sim::started("fd01::/120", 600, 600, PoolStart::Fresh { offset: 1 }, t0);
        // Every offset but the last stays mapped; the last expires.
        for i in 1..=255u32 {
            let vip = a.alloc_waiting(i).virtual_ip;
            if i < 255 {
                a.pinned.set(vip, 1);
            }
        }
        let last = a.pool.offset_addr(255);
        a.advance(Duration::from_secs(1300));
        assert!(
            a.pool.lookup_virtual_ip(&last).is_none(),
            "control: the last name expired"
        );
        assert_eq!(
            a.pool.offset_at(a.pool.cursor),
            1,
            "control: the cursor is just past it"
        );

        // The write covers a whole lap: the one free offset is just behind
        // the cursor. A pool this small asks for a write on every tick.
        let state = a.pool.mark_request().expect("no durable mark");
        a.pool.confirm_mark(&state);
        assert_eq!(state.span, 255, "control: a whole-lap stretch");
        let issued = a.alloc_waiting(1000).virtual_ip;
        assert_eq!(
            issued, last,
            "control: the name after the write takes the free offset"
        );

        let t1 = a.now + Duration::from_secs(1);
        let mut b = Sim::started("fd01::/120", 600, 600, PoolStart::Restored(state), t1);
        let next = b.alloc(2000);
        assert!(
            !matches!(next, Ok(Allocation { virtual_ip, .. }) if virtual_ip == issued),
            "an address issued in a whole-lap stretch was reissued after a restart"
        );
    }

    #[test]
    fn the_mark_is_never_passed_until_the_next_one_is_confirmed() {
        let t0 = Instant::now();
        let mut pool =
            VirtualIpPool::start("fd01::/112", 600, 600, PoolStart::Fresh { offset: 1 }, t0)
                .unwrap();
        assert!(
            matches!(
                pool.allocate_at(node_n(1), mesh_n(1), "test.fips", t0),
                Err(PoolError::AwaitingMark)
            ),
            "a started pool waits for its first write"
        );
        assert_eq!(pool.refused_total, 1);
        assert!(
            pool.refusals.open.is_some(),
            "the first refusal warns and latches"
        );

        let state = pool.mark_request().unwrap();
        pool.confirm_mark(&state);
        let mut now = t0;
        let mut issued = 0;
        let mut i = 1;
        loop {
            match pool.allocate_at(node_n(i), mesh_n(i), "test.fips", now) {
                Ok(_) => {
                    issued += 1;
                    i += 1;
                }
                Err(PoolError::RateLimited) => now += Duration::from_millis(100),
                Err(PoolError::AwaitingMark) => break,
                Err(e) => panic!("unexpected refusal: {e}"),
            }
        }
        assert_eq!(
            issued, MARK_RESERVE,
            "the pool issues exactly up to the mark"
        );
        assert!(matches!(
            pool.allocate_at(
                node_n(i),
                mesh_n(i),
                "test.fips",
                now + Duration::from_secs(1)
            ),
            Err(PoolError::AwaitingMark)
        ));
        assert_eq!(
            pool.refusals.open.map(|(_, count)| count),
            Some(3),
            "later refusals are counted in the open episode, not warned again"
        );

        let next = pool.mark_request().expect("the mark is reached");
        pool.confirm_mark(&next);
        assert!(
            pool.allocate_at(
                node_n(i),
                mesh_n(i),
                "test.fips",
                now + Duration::from_secs(2)
            )
            .is_ok(),
            "a confirmed mark lets allocation continue"
        );

        // The episode closes once nothing has been refused for the hold.
        pool.tick(now + Duration::from_secs(30), &Sessions::new().snapshot());
        assert!(pool.refusals.open.is_some(), "not yet");
        pool.tick(
            now + Duration::from_secs(1) + BOUND_LOG_HOLD,
            &Sessions::new().snapshot(),
        );
        assert!(
            pool.refusals.open.is_none(),
            "released after BOUND_LOG_HOLD"
        );
    }

    #[test]
    fn a_late_tick_at_full_rate_never_hits_the_mark() {
        let t0 = Instant::now();
        let mut pool =
            VirtualIpPool::start("fd01::/112", 600, 600, PoolStart::Fresh { offset: 1 }, t0)
                .unwrap();
        let state = pool.mark_request().unwrap();
        pool.confirm_mark(&state);

        // Allocate until exactly MARK_LOW_WATER free offsets are left before
        // the mark.
        let mut now = t0;
        let mut i = 1;
        while i <= MARK_RESERVE - MARK_LOW_WATER {
            match pool.allocate_at(node_n(i), mesh_n(i), "test.fips", now) {
                Ok(_) => i += 1,
                Err(PoolError::RateLimited) => now += Duration::from_millis(100),
                Err(e) => panic!("unexpected refusal: {e}"),
            }
        }
        pool.tick(now, &Sessions::new().snapshot());
        assert!(
            pool.mark_request().is_none(),
            "control: exactly MARK_LOW_WATER left is not yet a reason to write"
        );

        // Idle until the bucket is full, then no tick for 25 s at full rate.
        let start = now + Duration::from_secs(5);
        let mut admitted = 0;
        for step in 0..=250u32 {
            let at = start + Duration::from_millis(100) * step;
            loop {
                match pool.allocate_at(node_n(i), mesh_n(i), "test.fips", at) {
                    Ok(_) => {
                        admitted += 1;
                        i += 1;
                    }
                    Err(PoolError::RateLimited) => break,
                    Err(e) => panic!(
                        "allocation {} of a 25 s late tick at full rate was refused: {e}",
                        admitted + 1
                    ),
                }
            }
        }
        assert_eq!(
            admitted,
            MAPPING_BURST + MAPPING_RATE * 25,
            "control: a full bucket and 25 s at the full rate"
        );
    }

    #[test]
    fn a_run_of_mapped_addresses_ahead_of_the_cursor_does_not_starve_the_mark() {
        // A start whose previous run held 300 offsets directly ahead of the
        // cursor: the non-free run a new cursor can meet without a lap.
        let t0 = Instant::now();
        let state = PoolState {
            version: 1,
            pool: "fd01::/112".to_string(),
            total: 65535,
            from: 1,
            span: 0,
            held: vec![[1, 300]],
            hold_secs: 600,
        };
        let mut pool =
            VirtualIpPool::start("fd01::/112", 600, 600, PoolStart::Restored(state), t0).unwrap();
        let request = pool.mark_request().unwrap();
        assert_eq!(request.from, 1);
        assert_eq!(
            request.span,
            300 + MARK_RESERVE,
            "the mark covers the run plus MARK_RESERVE free offsets"
        );
        pool.confirm_mark(&request);
        let allocation = pool
            .allocate_at(node_n(1), mesh_n(1), "test.fips", t0)
            .expect("allocation continues");
        assert_eq!(pool.addr_offset(allocation.virtual_ip), Some(301));
    }

    #[test]
    fn restart_holds_release_after_the_loaded_hold_and_not_before() {
        let t0 = Instant::now();
        let state = PoolState {
            version: 1,
            pool: "fd01::/120".to_string(),
            total: 255,
            from: 1,
            span: 255,
            held: Vec::new(),
            hold_secs: 10,
        };
        let mut sim = Sim::started("fd01::/120", 5, 5, PoolStart::Restored(state), t0);
        assert!(
            matches!(sim.alloc(1), Err(PoolError::Exhausted(_))),
            "every offset is held from the previous run"
        );
        sim.advance(Duration::from_secs(9));
        assert!(matches!(sim.alloc(1), Err(PoolError::Exhausted(_))));

        sim.advance(Duration::from_secs(10 * u64::from(MAX_ABSENT_READS)));
        assert!(
            sim.alloc(1).is_ok(),
            "released after the hold and the reads"
        );

        // Past the hold with one read too few, the previous run's bindings
        // are not yet known, so nothing is released.
        let state = PoolState {
            version: 1,
            pool: "fd01::/120".to_string(),
            total: 255,
            from: 1,
            span: 255,
            held: Vec::new(),
            hold_secs: 10,
        };
        let mut pool =
            VirtualIpPool::start("fd01::/120", 5, 5, PoolStart::Restored(state), t0).unwrap();
        let request = pool.mark_request().unwrap();
        pool.confirm_mark(&request);
        let read = Sessions::new().snapshot();
        for k in 1..MAX_ABSENT_READS {
            pool.tick(t0 + Duration::from_secs(u64::from(k)), &read);
        }
        let past = t0 + Duration::from_secs(60);
        assert!(matches!(
            pool.allocate_at(node_n(1), mesh_n(1), "test.fips", past),
            Err(PoolError::Exhausted(_))
        ));
        pool.tick(past, &read);
        // The tick task writes the state that covers the released offsets.
        let request = pool.mark_request().unwrap();
        pool.confirm_mark(&request);
        assert!(
            pool.allocate_at(node_n(1), mesh_n(1), "test.fips", past)
                .is_ok()
        );
    }

    #[test]
    fn a_restored_pool_writes_a_hold_no_shorter_than_what_remains_of_its_loaded_one() {
        // The previous run held offsets 1-10 for longer than this run's TTL
        // plus grace, as after a restart with a lower DNS TTL.
        let t0 = Instant::now();
        let loaded = PoolState {
            version: 1,
            pool: "fd01::/120".to_string(),
            total: 255,
            from: 1,
            span: 0,
            held: vec![[1, 10]],
            hold_secs: 600,
        };
        let mut a = Sim::started("fd01::/120", 5, 5, PoolStart::Restored(loaded), t0);
        a.advance(Duration::from_secs(100));
        let remaining = 500;

        let crash = a.pool.mark_request().expect("a small pool asks again");
        let clean = a.pool.shutdown_state();
        for (name, state) in [("tick", &crash), ("shutdown", &clean)] {
            assert!(
                state.hold_secs >= remaining,
                "the {name} state holds offsets 1-10 for {} s, less than the {remaining} s \
                 left of the hold they were loaded with",
                state.hold_secs
            );
        }

        // The next run, after a crash, still refuses the earlier run's
        // offsets once its own TTL plus grace and its start reads are past.
        let waited = 10 + 10 * u64::from(MAX_ABSENT_READS) + 10;
        let mut c = Sim::started("fd01::/120", 5, 5, PoolStart::Restored(crash), a.now);
        c.advance(Duration::from_secs(waited));
        for i in 0..255 {
            match c.alloc(i) {
                Ok(allocation) => {
                    let offset = c.offset(allocation.virtual_ip);
                    assert!(
                        !(1..=10).contains(&offset),
                        "offset {offset}, held by the earlier run for {remaining} s more, \
                         was reissued after {waited} s"
                    );
                }
                Err(PoolError::Exhausted(_)) => break,
                Err(PoolError::RateLimited | PoolError::AwaitingMark) => {
                    c.advance(Duration::from_millis(100))
                }
                Err(e) => panic!("name {i} refused: {e}"),
            }
        }
        // Control: the refusal was the hold, and it ends.
        c.advance(Duration::from_secs(
            remaining + 10 * u64::from(MAX_ABSENT_READS),
        ));
        assert!(c.alloc(1000).is_ok(), "the hold never ended");
    }

    #[test]
    fn a_clean_shutdown_state_holds_only_live_addresses() {
        let t0 = Instant::now();
        let mut a = Sim::started("fd01::/120", 60, 60, PoolStart::Fresh { offset: 1 }, t0);
        let live: Vec<Ipv6Addr> = (1..=3).map(|i| a.alloc_waiting(i).virtual_ip).collect();

        let clean = a.pool.shutdown_state();
        let mut b = Sim::started("fd01::/120", 60, 60, PoolStart::Restored(clean), a.now);
        let next = b.alloc(10);
        assert!(
            next.is_ok(),
            "after a clean stop a new name resolves at once: {next:?}"
        );
        assert!(!live.contains(&next.unwrap().virtual_ip));

        // The state a crash would leave holds a whole lap on a small pool.
        let crash = a.pool.mark_request().unwrap();
        let mut c = Sim::started("fd01::/120", 60, 60, PoolStart::Restored(crash), a.now);
        assert!(matches!(c.alloc(10), Err(PoolError::Exhausted(_))));
    }

    #[test]
    fn a_new_name_at_the_ceiling_replaces_the_oldest_never_used_mapping() {
        let t0 = Instant::now();
        let mut pool = limited_pool(4, 5, 1);
        let mut vips = Vec::new();
        for i in 1..=4u8 {
            let at = t0 + Duration::from_secs(u64::from(i) - 1);
            vips.push(alloc(&mut pool, i, at).expect("below the ceiling").0);
        }
        let distinct: HashSet<Ipv6Addr> = vips.iter().copied().collect();
        assert_eq!(distinct.len(), 4, "control: four distinct addresses");

        let fifth = pool.allocate_at(
            make_node_addr(5),
            make_mesh_addr(5),
            "test.fips",
            t0 + Duration::from_secs(4),
        );
        let allocation = fifth.expect(
            "a LAN host holding the ceiling with names nobody uses must not lock \
             every other client out of new names",
        );
        assert_eq!(
            allocation.evicted,
            Some(Evicted {
                virtual_ip: vips[0],
                mesh_addr: make_mesh_addr(1),
            })
        );
        assert!(pool.lookup_virtual_ip(&vips[0]).is_none());
        for vip in &vips[1..] {
            assert!(
                pool.lookup_virtual_ip(vip).is_some(),
                "{vip} still resolves"
            );
        }
    }

    #[test]
    fn a_lan_host_requerying_a_thousand_unused_names_does_not_hold_the_ceiling() {
        let t0 = Instant::now();
        let mut pool = VirtualIpPool::new("fd01::/112", 60, 60).unwrap();
        let empty = Sessions::new();
        let step = Duration::from_millis(100);
        let mut last_query: Vec<Instant> = Vec::new();
        let mut next_tick = t0;
        let mut now = t0;

        // Admit MAPPING_CEILING names at the bucket rate, re-querying each
        // every 30 s, as a LAN host keeping them alive would.
        while last_query.len() < MAPPING_CEILING {
            if now >= next_tick {
                pool.tick(now, &empty.snapshot());
                next_tick += Duration::from_secs(10);
            }
            for (i, at) in last_query.iter_mut().enumerate() {
                if now.duration_since(*at) >= Duration::from_secs(30) {
                    let i = i as u32 + 1;
                    pool.allocate_at(node_n(i), mesh_n(i), "test.fips", now)
                        .expect("an existing name resolves");
                    *at = now;
                }
            }
            let i = last_query.len() as u32 + 1;
            match pool.allocate_at(node_n(i), mesh_n(i), "test.fips", now) {
                Ok(_) => last_query.push(now),
                Err(PoolError::RateLimited) => {}
                Err(e) => panic!("name {i} refused below the ceiling: {e}"),
            }
            now += step;
        }
        assert!(
            now < t0 + Duration::from_secs(120),
            "control: the fill finished before the first name's TTL and grace"
        );
        assert_eq!(pool.mapping_info(now).len(), MAPPING_CEILING, "control");

        // Wait for a token, then name one more.
        now += Duration::from_secs(1);
        let first_vip = pool
            .mappings
            .get(&node_n(1))
            .expect("name 1 is live")
            .virtual_ip;
        let next = MAPPING_CEILING as u32 + 1;
        let result = pool.allocate_at(node_n(next), mesh_n(next), "test.fips", now);
        assert!(
            !matches!(result, Err(PoolError::AtCeiling(_))),
            "one LAN host re-querying {MAPPING_CEILING} names nobody uses holds the \
             ceiling: {result:?}"
        );
        let allocation = result.expect("the new name is allocated");
        assert_eq!(
            allocation.evicted,
            Some(Evicted {
                virtual_ip: first_vip,
                mesh_addr: mesh_n(1),
            })
        );
    }

    /// A mesh address inside the `fd01::/16` pool prefix, for index `i`.
    fn mesh_in_pool(i: u32) -> Ipv6Addr {
        Ipv6Addr::new(0xfd01, (i >> 16) as u16, i as u16, 0x5678, 0, 0, 0, 9)
    }

    #[test]
    fn mesh_addresses_inside_a_wide_pool_prefix_cannot_hold_the_ceiling() {
        // The kernel routes the whole pool prefix to the gateway itself, so
        // traffic to a mesh address inside it is answered locally from that
        // address, a reply that would read as the mapping's own traffic. A
        // LAN host that names a thousand such nodes and pings each would
        // hold the ceiling with mappings that can never reach the mesh.
        let t0 = Instant::now();
        let mut pool =
            VirtualIpPool::with_limits("fd01::/16", 60, 60, MAPPING_CEILING, 10_000, 10_000)
                .unwrap();
        let mut replies = Sessions::new();
        for i in 1..=MAPPING_CEILING as u32 {
            if let Ok(allocation) = pool.allocate_at(node_n(i), mesh_in_pool(i), "x.fips", t0) {
                replies.bind(allocation.virtual_ip, mesh_in_pool(i), true);
            }
        }
        pool.tick(t0 + Duration::from_secs(10), &replies.snapshot());

        let next = MAPPING_CEILING as u32 + 1;
        let result = pool.allocate_at(
            node_n(next),
            mesh_n(next),
            "y.fips",
            t0 + Duration::from_secs(11),
        );
        assert!(
            result.is_ok(),
            "names whose mesh address lies inside the pool prefix hold the ceiling \
             against a name outside it: {result:?}"
        );
        let inside = pool.allocate_at(node_n(1), mesh_in_pool(1), "x.fips", t0);
        assert!(
            matches!(inside, Err(PoolError::InsidePool(_))),
            "a mesh address inside the pool prefix is not refused as such: {inside:?}"
        );
    }

    #[test]
    fn a_mesh_address_outside_the_pool_prefix_still_maps_when_it_shares_a_wider_prefix() {
        let t0 = Instant::now();
        let mut pool = VirtualIpPool::new("fd01::/112", 60, 60).unwrap();
        let mesh = Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 1, 9);
        let allocation = pool
            .allocate_at(node_n(1), mesh, "x.fips", t0)
            .expect("fd01::1:9 lies outside fd01::/112 and maps");
        assert!(allocation.is_new);
    }

    #[test]
    fn requerying_a_never_used_name_does_not_keep_it_past_ttl_and_grace() {
        let t0 = Instant::now();
        let mut pool = limited_pool(100, 10, 1);
        let empty = Sessions::new();
        let (vip, _) = alloc(&mut pool, 1, t0).unwrap();
        assert_eq!(
            alloc(&mut pool, 1, t0 + Duration::from_secs(59)).unwrap(),
            (vip, false),
            "control: the re-query returns the same address"
        );

        assert!(
            pool.tick(t0 + Duration::from_secs(70), &empty.snapshot())
                .is_empty()
        );
        let events = pool.tick(t0 + Duration::from_secs(131), &empty.snapshot());
        assert!(
            pool.lookup_virtual_ip(&vip).is_none(),
            "a re-query kept a name nobody used mapped past its TTL and grace"
        );
        assert!(matches!(
            events.as_slice(),
            [PoolEvent::MappingRemoved { .. }]
        ));
    }

    /// A `/120` pool with ceiling `ceiling`, TTL and grace `ttl` seconds,
    /// and a rate high enough never to refuse.
    fn fast_pool(ceiling: usize, ttl: u64) -> VirtualIpPool {
        VirtualIpPool::with_limits("fd01::/120", ttl, ttl, ceiling, 10_000, 10_000).unwrap()
    }

    /// The address at offset `offset` of a `fd01::/120` pool.
    fn at(offset: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, offset)
    }

    #[test]
    fn an_evicted_address_is_not_reissued_before_its_answer_deadline() {
        let t = Instant::now();
        let mut pool = fast_pool(4, 60);
        for i in 1..=4u32 {
            pool.allocate_at(node_n(i), mesh_n(i), "test.fips", t)
                .unwrap();
        }
        // Each further name replaces the oldest; the replaced addresses wait.
        let t1 = t + Duration::from_secs(1);
        for i in 5..=255u32 {
            let allocation = pool
                .allocate_at(node_n(i), mesh_n(i), "test.fips", t1)
                .unwrap_or_else(|e| panic!("name {i}: {e}"));
            assert_ne!(
                allocation.virtual_ip,
                at(1),
                "name {i} took the evicted address"
            );
            let evicted = allocation
                .evicted
                .expect("at the ceiling a name is replaced");
            pool.nat_removed(evicted.virtual_ip, evicted.mesh_addr);
        }
        let empty = Sessions::new();
        for k in 1..=MAX_ABSENT_READS {
            pool.tick(t1 + Duration::from_secs(u64::from(k)), &empty.snapshot());
        }
        // Control: the cursor has gone round to the evicted offset, and every
        // other address is mapped or waiting out its answers.
        assert_eq!(pool.offset_at(pool.cursor), 1, "control: the cursor lapped");
        assert!(
            matches!(
                pool.allocate_at(
                    node_n(256),
                    mesh_n(256),
                    "test.fips",
                    t1 + Duration::from_secs(5)
                ),
                Err(PoolError::Exhausted(4))
            ),
            "an evicted address was issued before its answer deadline"
        );

        let after = t + Duration::from_secs(121);
        pool.tick(after, &empty.snapshot());
        let reissued = pool
            .allocate_at(node_n(256), mesh_n(256), "test.fips", after)
            .expect("the address returns after its deadline");
        assert_eq!(reissued.virtual_ip, at(1));
    }

    #[test]
    fn a_reply_from_the_virtual_ip_itself_does_not_mark_a_mapping_used() {
        let t0 = Instant::now();
        let mut pool = fast_pool(10, 60);
        // The gateway's own local delivery of an unmapped pool address: the
        // reply tuple comes from the address itself.
        let mut ct = Sessions::new();
        ct.bind(at(1), at(1), true);
        pool.tick(t0, &ct.snapshot());

        let (vip, _) = alloc(&mut pool, 1, t0).unwrap();
        assert_eq!(
            vip,
            at(1),
            "control: the name got the address the entry names"
        );
        pool.tick(t0 + Duration::from_secs(10), &ct.snapshot());
        assert!(!pool.mappings[&make_node_addr(1)].used);
    }

    #[test]
    fn a_reply_from_a_previous_holders_mesh_address_does_not_mark_the_new_mapping_used() {
        let t0 = Instant::now();
        let mut pool = fast_pool(10, 60);
        let mut ct = Sessions::new();
        ct.bind(at(1), make_mesh_addr(1), true);
        pool.tick(t0, &ct.snapshot());

        let (vip, _) = alloc(&mut pool, 2, t0).unwrap();
        assert_eq!(vip, at(1), "control: the new holder got the address");
        pool.tick(t0 + Duration::from_secs(10), &ct.snapshot());
        assert!(!pool.mappings[&make_node_addr(2)].used);
    }

    /// The pool after node 1's mapping to the first address was replaced,
    /// its removal reported, and the cursor sent round the pool, followed by
    /// read ticks that each hold a forged reply on the old binding when the
    /// matching entry of `reads` is true and miss it when false. Returns the
    /// pool and the time of the last tick.
    fn pool_with_a_surviving_binding(reads: &[bool]) -> (VirtualIpPool, Instant) {
        let t0 = Instant::now();
        let mut pool = fast_pool(1, 5);
        let first = pool
            .allocate_at(make_node_addr(1), make_mesh_addr(1), "test.fips", t0)
            .unwrap();
        assert_eq!(first.virtual_ip, at(1));
        for i in 2..=255u32 {
            let allocation = pool
                .allocate_at(node_n(i), mesh_n(i), "test.fips", t0)
                .unwrap();
            let evicted = allocation.evicted.expect("ceiling 1 replaces every name");
            pool.nat_removed(evicted.virtual_ip, evicted.mesh_addr);
        }
        assert_eq!(pool.offset_at(pool.cursor), 1, "control: the cursor lapped");

        let mut forged = Sessions::new();
        forged.bind(at(1), make_mesh_addr(1), true);
        let partial = Sessions::new();
        let mut now = t0;
        for complete in reads {
            now += Duration::from_secs(10);
            let snapshot = if *complete { &forged } else { &partial };
            pool.tick(now, &snapshot.snapshot());
        }
        (pool, now)
    }

    #[test]
    fn an_address_is_not_given_back_to_a_node_whose_old_binding_to_it_survives() {
        let reads = [true; 3];
        let (mut attacked, now) = pool_with_a_surviving_binding(&reads);
        let (mut control, _) = pool_with_a_surviving_binding(&reads);

        let other = control
            .allocate_at(make_node_addr(2), make_mesh_addr(2), "test.fips", now)
            .unwrap();
        assert_eq!(
            other.virtual_ip,
            at(1),
            "control: another node gets the address"
        );

        let again = attacked
            .allocate_at(make_node_addr(1), make_mesh_addr(1), "test.fips", now)
            .unwrap();
        assert_ne!(
            again.virtual_ip,
            at(1),
            "the node was given back an address its forged old binding still names"
        );
        let mut forged = Sessions::new();
        forged.bind(at(1), make_mesh_addr(1), true);
        attacked.tick(now + Duration::from_secs(10), &forged.snapshot());
        assert!(!attacked.mappings[&make_node_addr(1)].used);
    }

    #[test]
    fn a_binding_missed_by_one_partial_read_still_blocks_the_reissue() {
        // The read just before the name is asked for misses the entry.
        let (mut pool, now) = pool_with_a_surviving_binding(&[true, true, true, false]);
        let again = pool
            .allocate_at(make_node_addr(1), make_mesh_addr(1), "test.fips", now)
            .unwrap();
        assert_ne!(
            again.virtual_ip,
            at(1),
            "one partial read dropped the binding"
        );

        let mut forged = Sessions::new();
        forged.bind(at(1), make_mesh_addr(1), true);
        pool.tick(now + Duration::from_secs(10), &forged.snapshot());
        assert!(!pool.mappings[&make_node_addr(1)].used);
    }

    #[test]
    fn unread_ticks_do_not_age_a_surviving_binding() {
        // Failed reads too few to turn evidence off, then one partial read.
        let follow = |pool: &mut VirtualIpPool, mut now: Instant| {
            for _ in 1..MAX_UNREAD_TICKS {
                now += Duration::from_secs(10);
                pool.tick(now, &ConntrackSnapshot::default());
            }
            now += Duration::from_secs(10);
            pool.tick(now, &Sessions::new().snapshot());
            now
        };
        let (mut pool, now) = pool_with_a_surviving_binding(&[true; 3]);
        let now = follow(&mut pool, now);
        let (mut control, then) = pool_with_a_surviving_binding(&[true; 3]);
        let then = follow(&mut control, then);
        assert!(control.evidence.trusted, "control: evidence is still on");
        let other = control
            .allocate_at(make_node_addr(2), make_mesh_addr(2), "test.fips", then)
            .unwrap();
        assert_eq!(
            other.virtual_ip,
            at(1),
            "control: the cursor is at the address and it is free"
        );

        let again = pool
            .allocate_at(make_node_addr(1), make_mesh_addr(1), "test.fips", now)
            .unwrap();
        assert_ne!(
            again.virtual_ip,
            at(1),
            "unread ticks and one partial read dropped the binding"
        );
    }

    #[test]
    fn a_removed_address_waits_for_its_nat_removal_and_later_reads() {
        let t0 = Instant::now();
        let mut pool = fast_pool(1, 60);
        let (x, _) = alloc(&mut pool, 1, t0).unwrap();
        let replaced = pool
            .allocate_at(make_node_addr(2), make_mesh_addr(2), "test.fips", t0)
            .unwrap();
        assert!(
            replaced.evicted.is_some(),
            "control: the first name was replaced"
        );
        let offset = pool.addr_offset(x).unwrap();
        let read = Sessions::new().snapshot();
        let unread = ConntrackSnapshot::default();

        let past = t0 + Duration::from_secs(121);
        pool.tick(past, &read);
        assert!(!pool.free.contains(&offset), "free before its NAT removal");
        pool.nat_removed(x, make_mesh_addr(1));
        pool.tick(past + Duration::from_secs(10), &unread);
        assert!(!pool.free.contains(&offset), "free after an unread tick");
        for k in 1..MAX_ABSENT_READS {
            pool.tick(past + Duration::from_secs(10 + 10 * u64::from(k)), &read);
            assert!(!pool.free.contains(&offset), "free after {k} read(s)");
        }
        pool.tick(
            past + Duration::from_secs(10 + 10 * u64::from(MAX_ABSENT_READS)),
            &read,
        );
        assert!(pool.free.contains(&offset), "free after the last read");
    }

    #[test]
    fn a_pinned_never_used_address_is_held_for_grace_after_its_last_answer() {
        let t0 = Instant::now();
        let mut pool = fast_pool(1, 60);
        let (x, _) = alloc(&mut pool, 1, t0).unwrap();
        let mut pinned = Sessions::new();
        pinned.set(x, 1);
        pinned.bind(x, make_mesh_addr(1), false);
        let mut now = t0;
        while now < t0 + Duration::from_secs(200) {
            now += Duration::from_secs(10);
            pool.tick(now, &pinned.snapshot());
        }
        let requery = pool
            .allocate_at(make_node_addr(1), make_mesh_addr(1), "test.fips", now)
            .unwrap();
        assert_eq!(
            (requery.virtual_ip, requery.ttl),
            (x, 0),
            "control: TTL 0 past its deadline"
        );

        let t = now;
        let evicting = pool
            .allocate_at(
                make_node_addr(2),
                make_mesh_addr(2),
                "test.fips",
                t + Duration::from_secs(1),
            )
            .unwrap();
        let evicted = evicting
            .evicted
            .expect("control: the pinned name was replaced");
        pool.nat_removed(evicted.virtual_ip, evicted.mesh_addr);
        let offset = pool.addr_offset(x).unwrap();
        let read = Sessions::new().snapshot();
        for k in 1..=5u64 {
            pool.tick(t + Duration::from_secs(1 + k), &read);
        }
        assert!(
            !pool.free.contains(&offset),
            "released before grace after its last answer, which a client may still cache"
        );
        pool.tick(t + Duration::from_secs(61), &read);
        assert!(pool.free.contains(&offset), "released after grace");
    }

    #[test]
    fn evidence_recovers_after_a_failed_start_probe_once_reads_succeed() {
        let t0 = Instant::now();
        let mut pool = fast_pool(10, 600);
        pool.set_evidence(false);
        let (before, _) = alloc(&mut pool, 1, t0).unwrap();
        assert!(
            pool.mappings[&make_node_addr(1)].blind,
            "a mapping made with no readable source is blind"
        );

        let mut now = t0;
        for _ in 0..MAX_ABSENT_READS {
            now += Duration::from_secs(10);
            pool.tick(now, &ConntrackSnapshot::empty_read());
        }
        assert!(
            pool.evidence.trusted,
            "evidence is not trusted after MAX_ABSENT_READS good reads that followed a failed start probe"
        );
        let (after, _) = alloc(&mut pool, 2, now).unwrap();
        let mut replies = Sessions::new();
        replies.bind(before, make_mesh_addr(1), true);
        replies.bind(after, make_mesh_addr(2), true);
        now += Duration::from_secs(10);
        pool.tick(now, &replies.snapshot());
        assert!(
            pool.mappings[&make_node_addr(2)].used,
            "a replied mapping made after the source became readable is not used"
        );
        assert!(
            !pool.mappings[&make_node_addr(1)].used,
            "a mapping made while no source was readable became used"
        );
    }

    #[test]
    fn a_mapping_made_before_a_started_pool_has_enough_reads_cannot_become_used() {
        // The previous run left a conntrack entry binding offset 1 to node
        // 1's mesh address with a reply, and the one start read missed it.
        let t0 = Instant::now();
        let start = PoolStart::Fresh { offset: 1 };
        let mut pool = VirtualIpPool::start("fd01::/112", 600, 600, start, t0).unwrap();
        let state = pool.mark_request().expect("a fresh pool asks for a mark");
        pool.confirm_mark(&state);
        pool.tick(t0, &ConntrackSnapshot::empty_read());

        let (reissued, _) = alloc(&mut pool, 1, t0).unwrap();
        let mut old = Sessions::new();
        old.bind(reissued, make_mesh_addr(1), true);
        let mut now = t0;
        for _ in 1..MAX_ABSENT_READS {
            now += Duration::from_secs(10);
            pool.tick(now, &old.snapshot());
        }
        assert!(
            !pool.mappings[&make_node_addr(1)].used,
            "a mapping made after one start read was marked used by a binding that read missed"
        );

        // Once enough reads have been taken, a real reply marks a new mapping.
        let (fresh, _) = alloc(&mut pool, 2, now).unwrap();
        let mut replies = old;
        replies.bind(fresh, make_mesh_addr(2), true);
        now += Duration::from_secs(10);
        pool.tick(now, &replies.snapshot());
        assert!(
            pool.mappings[&make_node_addr(2)].used,
            "a replied mapping made after MAX_ABSENT_READS reads is not used"
        );
    }

    #[test]
    fn without_evidence_removed_addresses_wait_only_for_their_deadline_and_nat_removal() {
        let t0 = Instant::now();
        let mut pool = fast_pool(1, 60);
        pool.set_evidence(false);
        let (x, _) = alloc(&mut pool, 1, t0).unwrap();
        alloc(&mut pool, 2, t0).unwrap();
        let offset = pool.addr_offset(x).unwrap();
        let unread = ConntrackSnapshot::default();

        let past = t0 + Duration::from_secs(121);
        pool.tick(past, &unread);
        assert!(!pool.free.contains(&offset), "free before its NAT removal");
        pool.nat_removed(x, make_mesh_addr(1));
        pool.tick(past + Duration::from_secs(10), &unread);
        assert!(
            pool.free.contains(&offset),
            "free at the next tick, with no read"
        );
    }

    #[test]
    fn evidence_turns_off_after_unread_ticks_and_back_on_after_enough_reads() {
        let t0 = Instant::now();
        let mut pool = fast_pool(10, 600);
        let (before, _) = alloc(&mut pool, 1, t0).unwrap();
        let unread = ConntrackSnapshot::default();
        let mut now = t0;
        for _ in 0..MAX_UNREAD_TICKS {
            now += Duration::from_secs(10);
            pool.tick(now, &unread);
        }
        assert!(
            !pool.evidence.trusted,
            "off after MAX_UNREAD_TICKS unread ticks"
        );
        let (during, _) = alloc(&mut pool, 2, now).unwrap();
        assert!(pool.mappings[&make_node_addr(2)].blind);

        // One read is not enough to trust a rebuilt set of bindings.
        now += Duration::from_secs(10);
        pool.tick(now, &Sessions::new().snapshot());
        assert!(!pool.evidence.trusted, "still off after one read");
        let (recovering, _) = alloc(&mut pool, 3, now).unwrap();

        let mut replies = Sessions::new();
        replies.bind(before, make_mesh_addr(1), true);
        replies.bind(during, make_mesh_addr(2), true);
        replies.bind(recovering, make_mesh_addr(3), true);
        for _ in 1..MAX_ABSENT_READS {
            now += Duration::from_secs(10);
            pool.tick(now, &replies.snapshot());
        }
        assert!(
            pool.evidence.trusted,
            "back on after MAX_ABSENT_READS reads"
        );
        assert!(
            pool.mappings[&make_node_addr(1)].used,
            "a mapping from before the outage is marked by a reply"
        );
        assert!(
            !pool.mappings[&make_node_addr(2)].used,
            "a mapping created while evidence was off became used"
        );
        assert!(
            !pool.mappings[&make_node_addr(3)].used,
            "a mapping created while evidence was recovering became used"
        );
    }

    #[test]
    fn a_used_mapping_stays_protected_while_evidence_is_off() {
        let t0 = Instant::now();
        let mut pool = fast_pool(4, 600);
        let (vip, _) = alloc(&mut pool, 1, t0).unwrap();
        mark_used(&mut pool, 1, t0);
        let unread = ConntrackSnapshot::default();
        let mut now = t0;
        for _ in 0..MAX_UNREAD_TICKS {
            now += Duration::from_secs(10);
            pool.tick(now, &unread);
        }
        assert!(!pool.evidence.trusted, "control: evidence is off");
        for i in 100..(100 + 2 * 4u32) {
            let allocation = pool
                .allocate_at(node_n(i), mesh_n(i), "test.fips", now)
                .unwrap();
            assert_ne!(allocation.evicted.map(|e| e.virtual_ip), Some(vip));
        }
        let before = pool.mappings[&make_node_addr(1)].last_referenced;
        let requery = alloc(&mut pool, 1, now + Duration::from_secs(1)).unwrap();
        assert_eq!(requery, (vip, false));
        assert!(pool.mappings[&make_node_addr(1)].last_referenced > before);
    }

    #[test]
    fn an_eviction_spends_a_token() {
        let t0 = Instant::now();
        let mut pool = limited_pool(2, 2, 1);
        alloc(&mut pool, 1, t0).unwrap();
        alloc(&mut pool, 2, t0).unwrap();
        assert!(matches!(
            alloc(&mut pool, 3, t0),
            Err(PoolError::RateLimited)
        ));
        assert_eq!(pool.mappings.len(), 2, "nothing was replaced");
        assert_eq!(pool.evicted_total, 0);
    }

    #[test]
    fn a_never_used_answer_never_outlives_its_ttl_from_creation() {
        let t0 = Instant::now();
        let mut pool = fast_pool(10, 60);
        alloc(&mut pool, 1, t0).unwrap();
        let requery = |pool: &mut VirtualIpPool, secs: u64| {
            pool.allocate_at(
                make_node_addr(1),
                make_mesh_addr(1),
                "test.fips",
                t0 + Duration::from_secs(secs),
            )
            .unwrap()
            .ttl
        };
        assert_eq!(requery(&mut pool, 40), 20);
        assert_eq!(requery(&mut pool, 100), 0);
        mark_used(&mut pool, 1, t0 + Duration::from_secs(101));
        assert_eq!(
            requery(&mut pool, 102),
            60,
            "a used mapping gets the full TTL"
        );
    }

    #[test]
    fn a_used_mapping_survives_a_flood_that_fills_the_ceiling() {
        let t0 = Instant::now();
        let mut pool = fast_pool(4, 600);
        let (vip, _) = alloc(&mut pool, 1, t0).unwrap();
        mark_used(&mut pool, 1, t0);
        for i in 100..(100 + 2 * 4u32) {
            let allocation = pool
                .allocate_at(node_n(i), mesh_n(i), "test.fips", t0)
                .unwrap();
            assert_ne!(allocation.evicted.map(|e| e.virtual_ip), Some(vip));
        }
        assert_eq!(alloc(&mut pool, 1, t0).unwrap(), (vip, false));
        assert_eq!(pool.mappings.len(), 4);
    }

    #[test]
    fn a_pinned_never_used_mapping_stays_mapped_below_the_ceiling() {
        let t0 = Instant::now();
        let mut pool = fast_pool(10, 60);
        let (vip, _) = alloc(&mut pool, 1, t0).unwrap();
        let mut pinned = Sessions::new();
        pinned.set(vip, 1);
        pinned.bind(vip, make_mesh_addr(1), false);
        let mut now = t0;
        while now < t0 + Duration::from_secs(300) {
            now += Duration::from_secs(10);
            assert!(pool.tick(now, &pinned.snapshot()).is_empty());
        }
        let answer = pool
            .allocate_at(make_node_addr(1), make_mesh_addr(1), "test.fips", now)
            .unwrap();
        assert_eq!((answer.virtual_ip, answer.ttl), (vip, 0));
        assert!(!pool.mappings[&make_node_addr(1)].used);
    }

    /// A conntrack line for a flow DNAT'd from virtual IP `fd01::5` to mesh
    /// address `fd9a::2`, in the form the kernel prints (see `KERNEL_LINE`):
    /// the LAN client `fd02::20` to the virtual IP, and back from the mesh
    /// address to the gateway's fips0 address `fd9a::1`.
    const DNAT_LINE: &str = "ipv6     10 tcp      6 431999 ESTABLISHED \
         src=fd02:0000:0000:0000:0000:0000:0000:0020 \
         dst=fd01:0000:0000:0000:0000:0000:0000:0005 sport=45678 dport=8000 \
         src=fd9a:0000:0000:0000:0000:0000:0000:0002 \
         dst=fd9a:0000:0000:0000:0000:0000:0000:0001 sport=8000 dport=45678 \
         [ASSURED] mark=0 use=1";

    /// The same flow over UDP, never answered: the kernel prints
    /// `[UNREPLIED]` between the tuples.
    const UNREPLIED_LINE: &str = "ipv6     10 udp      17 29 \
         src=fd02:0000:0000:0000:0000:0000:0000:0020 \
         dst=fd01:0000:0000:0000:0000:0000:0000:0005 sport=45678 dport=9 \
         [UNREPLIED] src=fd9a:0000:0000:0000:0000:0000:0000:0002 \
         dst=fd9a:0000:0000:0000:0000:0000:0000:0001 sport=9 dport=45678 \
         mark=0 use=1";

    #[test]
    fn conntrack_parse_records_the_reply_source_of_a_replied_dnat_line() {
        let snapshot = parse_conntrack(DNAT_LINE);
        let vip: Ipv6Addr = "fd01::5".parse().unwrap();
        let mesh: Ipv6Addr = "fd9a::2".parse().unwrap();

        assert!(snapshot.bound_to(vip, mesh));
        assert!(snapshot.replied_from(vip, mesh));
        assert!(
            !snapshot.bound_to(vip, vip),
            "the original destination is not its own reply source"
        );
        assert_eq!(snapshot.sessions_for(vip), 1, "pinning is unchanged");
    }

    #[test]
    fn conntrack_parse_ignores_the_reply_of_an_unreplied_line() {
        let snapshot = parse_conntrack(UNREPLIED_LINE);
        let vip: Ipv6Addr = "fd01::5".parse().unwrap();
        let mesh: Ipv6Addr = "fd9a::2".parse().unwrap();

        assert!(snapshot.bound_to(vip, mesh), "the binding is recorded");
        assert!(!snapshot.replied_from(vip, mesh), "but not as a reply");
        assert_eq!(snapshot.sessions_for(vip), 1, "pinning is unchanged");
    }

    #[test]
    fn test_mapping_lifecycle_allocated_to_free() {
        let mut pool = VirtualIpPool::new("fd01::/120", 1, 1).unwrap();
        let ct = Sessions::new();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);

        pair(pool.allocate(node, mesh, "test.fips").unwrap());

        // Tick before TTL — no change
        let now = Instant::now();
        let events = pool.tick(now, &ct.snapshot());
        assert!(events.is_empty());
        assert_eq!(pool.mappings.len(), 1);

        // Tick after TTL with no sessions — enters draining
        let later = now + std::time::Duration::from_secs(2);
        let events = pool.tick(later, &ct.snapshot());
        assert!(events.is_empty());
        assert_eq!(pool.mappings.len(), 1);
        assert_eq!(
            pool.mappings.values().next().unwrap().state,
            MappingState::Draining
        );

        // Tick after grace period — freed
        let after_grace = later + std::time::Duration::from_secs(2);
        let events = pool.tick(after_grace, &ct.snapshot());
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], PoolEvent::MappingRemoved { .. }));
        assert_eq!(pool.mappings.len(), 0);

        // Returned to the pool once its NAT removal is reported and later
        // reads have shown no entry still binds it.
        if let PoolEvent::MappingRemoved {
            virtual_ip,
            mesh_addr,
        } = events[0]
        {
            pool.nat_removed(virtual_ip, mesh_addr);
        }
        for k in 1..=MAX_ABSENT_READS {
            pool.tick(
                after_grace + Duration::from_secs(u64::from(k)),
                &ct.snapshot(),
            );
        }
        assert_eq!(pool.free.len(), 255); // returned to pool
    }

    #[test]
    fn dns_renewal_preserves_the_full_ttl_after_draining() {
        let t0 = Instant::now();
        let mut pool = VirtualIpPool::with_limits("fd01::/120", 60, 60, 1, 1, 1).unwrap();
        let ct = Sessions::new().snapshot();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);
        let (vip, _) = pair(pool.allocate_at(node, mesh, "test.fips", t0).unwrap());
        mark_used(&mut pool, 1, t0);

        pool.tick(t0 + Duration::from_secs(61), &ct);
        assert_eq!(pool.mappings[&node].state, MappingState::Draining);

        // Renew just before the old grace period ends, with admission full.
        // The answer reuses the same address and promises another 60s TTL.
        let renewed = t0 + Duration::from_secs(120);
        let renewal = pool.allocate_at(node, mesh, "test.fips", renewed).unwrap();
        assert_eq!(pair(renewal.clone()), (vip, false));
        assert_eq!(
            renewal.ttl, 60,
            "a used mapping is answered with the full TTL"
        );
        assert_eq!(pool.bucket.tokens(), 0);
        assert!(pool.tick(t0 + Duration::from_secs(122), &ct).is_empty());
        assert!(pool.tick(renewed + Duration::from_secs(60), &ct).is_empty());
        assert_eq!(pool.lookup_virtual_ip(&vip).unwrap().node_addr, node);
        assert_eq!(pool.mappings[&node].state, MappingState::Allocated);

        // An idle mapping still expires after its renewed TTL and a fresh
        // grace period; renewal must not make addresses immortal.
        let drained = renewed + Duration::from_secs(61);
        assert!(pool.tick(drained, &ct).is_empty());
        assert_eq!(pool.mappings[&node].state, MappingState::Draining);
        assert!(pool.tick(drained + Duration::from_secs(60), &ct).is_empty());
        let events = pool.tick(drained + Duration::from_secs(61), &ct);
        assert!(matches!(
            events.as_slice(),
            [PoolEvent::MappingRemoved { .. }]
        ));
        assert!(pool.lookup_virtual_ip(&vip).is_none());
    }

    #[test]
    fn dns_refresh_without_an_address_cancels_draining() {
        let now = Instant::now();
        let mut pool = VirtualIpPool::new("fd01::/120", 60, 10).unwrap();
        let ct = Sessions::new().snapshot();
        let node = make_node_addr(1);
        let created = now - Duration::from_secs(62);
        pool.allocate_at(node, make_mesh_addr(1), "test.fips", created)
            .unwrap();
        mark_used(&mut pool, 1, created);
        pool.tick(now - Duration::from_secs(1), &ct);
        assert_eq!(pool.mappings[&node].state, MappingState::Draining);

        // A/other queries refresh existing mappings without creating one.
        assert!(pool.refresh_if_present(node));
        assert!(!pool.refresh_if_present(make_node_addr(2)));
        assert_eq!(pool.mappings.len(), 1);
        assert!(pool.tick(now + Duration::from_secs(11), &ct).is_empty());
        assert_eq!(pool.mappings[&node].state, MappingState::Allocated);
        assert!(pool.mappings[&node].drain_start.is_none());
    }

    #[test]
    fn test_mapping_lifecycle_active_draining_free() {
        let mut pool = VirtualIpPool::new("fd01::/120", 1, 1).unwrap();
        let mut ct = Sessions::new();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);

        let (vip, _) = pair(pool.allocate(node, mesh, "test.fips").unwrap());

        // Simulate active sessions
        ct.set(vip, 3);
        let now = Instant::now();
        let events = pool.tick(now, &ct.snapshot());
        assert!(events.is_empty());
        assert_eq!(pool.mappings[&node].state, MappingState::Active);

        // TTL expires after sessions drop to 0 → Draining
        let later = now + std::time::Duration::from_secs(2);
        ct.set(vip, 0);
        let events = pool.tick(later, &ct.snapshot());
        assert!(events.is_empty());
        assert_eq!(pool.mappings[&node].state, MappingState::Draining);

        // Still draining, grace period not elapsed
        let events = pool.tick(later, &ct.snapshot());
        assert!(events.is_empty());
        assert_eq!(pool.mappings[&node].state, MappingState::Draining);

        // Grace period elapsed → Free
        let much_later = later + std::time::Duration::from_secs(2);
        let events = pool.tick(much_later, &ct.snapshot());
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], PoolEvent::MappingRemoved { .. }));
        assert_eq!(pool.mappings.len(), 0);
    }

    #[test]
    fn test_active_traffic_never_reclaimed() {
        // A mapping with continuous sessions > 0 across many ticks
        // spanning well past the TTL must never be reclaimed and must
        // stay Active: live traffic refreshes last_referenced each tick.
        let mut pool = VirtualIpPool::new("fd01::/120", 1, 1).unwrap();
        let mut ct = Sessions::new();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);

        let (vip, _) = pair(pool.allocate(node, mesh, "test.fips").unwrap());
        ct.set(vip, 2);

        let mut t = Instant::now();
        // First tick activates the mapping.
        let events = pool.tick(t, &ct.snapshot());
        assert!(events.is_empty());
        assert_eq!(pool.mappings[&node].state, MappingState::Active);

        // Advance many TTL-spans with continuous traffic.
        for _ in 0..10 {
            t += std::time::Duration::from_secs(5); // 5x the 1s TTL
            let events = pool.tick(t, &ct.snapshot());
            assert!(events.is_empty(), "mapping must not be reclaimed");
            assert_eq!(
                pool.mappings[&node].state,
                MappingState::Active,
                "mapping must stay Active while traffic flows"
            );
        }
        assert_eq!(pool.mappings.len(), 1);
    }

    #[test]
    fn test_bursty_draining_recovers_to_active() {
        // Active -> drains when sessions hit 0 -> regains sessions before
        // grace elapses -> recovers to Active and is not freed.
        let mut pool = VirtualIpPool::new("fd01::/120", 1, 5).unwrap();
        let mut ct = Sessions::new();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);

        let (vip, _) = pair(pool.allocate(node, mesh, "test.fips").unwrap());

        // Activate with traffic.
        ct.set(vip, 1);
        let now = Instant::now();
        let events = pool.tick(now, &ct.snapshot());
        assert!(events.is_empty());
        assert_eq!(pool.mappings[&node].state, MappingState::Active);

        // TTL passes with sessions dropping to 0 -> Draining.
        let drained = now + std::time::Duration::from_secs(2);
        ct.set(vip, 0);
        let events = pool.tick(drained, &ct.snapshot());
        assert!(events.is_empty());
        assert_eq!(pool.mappings[&node].state, MappingState::Draining);

        // Traffic resumes before grace (5s) elapses -> recover to Active.
        let resumed = drained + std::time::Duration::from_secs(2);
        ct.set(vip, 3);
        let events = pool.tick(resumed, &ct.snapshot());
        assert!(events.is_empty());
        assert_eq!(pool.mappings[&node].state, MappingState::Active);
        assert!(pool.mappings[&node].drain_start.is_none());
        assert_eq!(pool.mappings.len(), 1);
    }

    #[test]
    fn test_redrain_honors_fresh_grace_window() {
        // After recovering from Draining, a subsequent drain must get a
        // fresh drain_start so the full grace window is honored again,
        // not reclaimed immediately off a stale drain_start.
        let mut pool = VirtualIpPool::new("fd01::/120", 1, 5).unwrap();
        let mut ct = Sessions::new();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);

        let (vip, _) = pair(pool.allocate(node, mesh, "test.fips").unwrap());

        // Activate.
        ct.set(vip, 1);
        let now = Instant::now();
        pool.tick(now, &ct.snapshot());
        assert_eq!(pool.mappings[&node].state, MappingState::Active);

        // First drain.
        let first_drain = now + std::time::Duration::from_secs(2);
        ct.set(vip, 0);
        pool.tick(first_drain, &ct.snapshot());
        assert_eq!(pool.mappings[&node].state, MappingState::Draining);

        // Recover.
        let recover = first_drain + std::time::Duration::from_secs(2);
        ct.set(vip, 2);
        pool.tick(recover, &ct.snapshot());
        assert_eq!(pool.mappings[&node].state, MappingState::Active);

        // Second drain begins; drain_start must be re-stamped fresh.
        let second_drain = recover + std::time::Duration::from_secs(2);
        ct.set(vip, 0);
        pool.tick(second_drain, &ct.snapshot());
        assert_eq!(pool.mappings[&node].state, MappingState::Draining);

        // Just before the fresh grace window expires (5s): not reclaimed.
        let before_grace = second_drain + std::time::Duration::from_secs(4);
        let events = pool.tick(before_grace, &ct.snapshot());
        assert!(events.is_empty(), "fresh grace window must be honored");
        assert_eq!(pool.mappings.len(), 1);

        // After the fresh grace window: reclaimed.
        let after_grace = second_drain + std::time::Duration::from_secs(6);
        let events = pool.tick(after_grace, &ct.snapshot());
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], PoolEvent::MappingRemoved { .. }));
        assert_eq!(pool.mappings.len(), 0);
    }

    #[test]
    fn test_pool_status() {
        let mut pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
        let status = pool.status();
        assert_eq!(status.total, 255);
        assert_eq!(status.free, 255);
        assert_eq!(status.allocated, 0);

        pool.allocate(make_node_addr(1), make_mesh_addr(1), "test.fips")
            .unwrap();
        let status = pool.status();
        assert_eq!(status.allocated, 1);
        assert_eq!(status.free, 254);
    }

    #[test]
    fn test_lookup_virtual_ip() {
        let mut pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);

        let (vip, _) = pair(pool.allocate(node, mesh, "test.fips").unwrap());
        let mapping = pool.lookup_virtual_ip(&vip).unwrap();
        assert_eq!(mapping.node_addr, node);
        assert_eq!(mapping.mesh_addr, mesh);

        let unknown: Ipv6Addr = "fd01::ff".parse().unwrap();
        assert!(pool.lookup_virtual_ip(&unknown).is_none());
    }

    #[test]
    fn test_large_prefix_capped() {
        // /96 = 32 host bits, but pool caps at 2^16
        let pool = VirtualIpPool::new("fd01::/96", 60, 60).unwrap();
        assert_eq!(pool.total, 65535); // 2^16 - 1 (skip addr 0)
    }

    /// A conntrack line in the form the kernel prints.
    ///
    /// Built from the kernel's own format string, not captured from a running
    /// kernel: `net/netfilter/nf_conntrack_standalone.c` prints each tuple with
    /// `"src=%pI6 dst=%pI6 "`, and `%pI6` is the full uncompressed form with
    /// leading zeros (`Documentation/core-api/printk-formats.rst`). Both were
    /// read at v6.8. The host this was written on has no
    /// `/proc/net/nf_conntrack` to capture from, because its kernel is built
    /// without `CONFIG_NF_CONNTRACK_PROCFS`; OpenWrt's generic kernel config
    /// sets it, which is the kernel this parser exists for.
    const KERNEL_LINE: &str = "ipv6     10 tcp      6 431999 ESTABLISHED \
         src=fd02:0000:0000:0000:0000:0000:0000:0020 \
         dst=fd01:0000:0000:0000:0000:0000:0000:0001 sport=45678 dport=8000 \
         src=fd01:0000:0000:0000:0000:0000:0000:0001 \
         dst=fd02:0000:0000:0000:0000:0000:0000:0020 sport=8000 dport=45678 \
         [ASSURED] mark=0 use=1";

    #[test]
    fn conntrack_parse_counts_a_kernel_format_line_for_its_virtual_ip() {
        let counts = parse_conntrack(KERNEL_LINE);
        let virtual_ip: Ipv6Addr = "fd01::1".parse().unwrap();

        assert_eq!(
            counts.sessions_for(virtual_ip),
            1,
            "the kernel writes the uncompressed form, so matching on the \
             address's compressed Display form counts nothing"
        );

        // Healthy path: a different address in the same pool is not counted.
        let other: Ipv6Addr = "fd01::10".parse().unwrap();
        assert_eq!(counts.sessions_for(other), 0);
    }

    #[test]
    fn conntrack_parse_counts_a_line_once_however_many_tuples_name_the_address() {
        // A hairpin flow: the address is the destination of both tuples.
        let line = "ipv6     10 udp      17 29 \
             src=fd01:0000:0000:0000:0000:0000:0000:0001 \
             dst=fd01:0000:0000:0000:0000:0000:0000:0001 sport=1 dport=2 \
             src=fd01:0000:0000:0000:0000:0000:0000:0001 \
             dst=fd01:0000:0000:0000:0000:0000:0000:0001 sport=2 dport=1 \
             mark=0 use=1";
        let counts = parse_conntrack(line);
        let virtual_ip: Ipv6Addr = "fd01::1".parse().unwrap();

        assert_eq!(counts.sessions_for(virtual_ip), 1);
    }

    #[test]
    fn conntrack_parse_counts_each_line_that_names_the_address() {
        let content = format!("{KERNEL_LINE}\n{KERNEL_LINE}\n");
        let counts = parse_conntrack(&content);
        let virtual_ip: Ipv6Addr = "fd01::1".parse().unwrap();

        assert_eq!(counts.sessions_for(virtual_ip), 2);
    }

    #[test]
    fn conntrack_parse_skips_a_value_that_is_not_an_ipv6_address() {
        let content = "ipv4     2 tcp      6 431999 ESTABLISHED src=192.0.2.1 \
             dst=192.0.2.2 sport=1 dport=2 mark=0 use=1\n";

        assert!(parse_conntrack(content).is_empty());
    }

    #[test]
    fn conntrack_snapshot_reads_zero_for_an_address_it_did_not_see() {
        let snapshot = parse_conntrack(KERNEL_LINE);

        assert_eq!(snapshot.sessions_for("fd01::1".parse().unwrap()), 1);
        assert_eq!(snapshot.sessions_for("fd01::99".parse().unwrap()), 0);
        assert!(ConntrackSnapshot::default().is_empty());
    }

    #[test]
    fn conntrack_read_log_warns_on_a_new_outcome_and_not_on_a_repeat() {
        use std::io::ErrorKind;

        let mut log = ConntrackReadLog::default();

        // The sequence a kernel without the proc file produces, then a source
        // that comes back, then fails again.
        assert_eq!(log.observe(Some(ErrorKind::NotFound)), ReadReport::Changed);
        assert_eq!(log.observe(Some(ErrorKind::NotFound)), ReadReport::Repeated);
        assert_eq!(log.observe(None), ReadReport::Changed);
        assert_eq!(log.observe(None), ReadReport::Repeated);
        assert_eq!(log.observe(Some(ErrorKind::NotFound)), ReadReport::Changed);
        assert_eq!(
            log.observe(Some(ErrorKind::PermissionDenied)),
            ReadReport::Changed,
            "a different failure is a different outcome and is worth a line"
        );
    }

    /// A conntrack querier that succeeds with an empty snapshot, or fails with
    /// a fixed error kind.
    struct FixedRead(Option<std::io::ErrorKind>);

    impl ConntrackQuerier for FixedRead {
        fn snapshot(&self) -> Result<ConntrackSnapshot, std::io::Error> {
            match self.0 {
                None => Ok(ConntrackSnapshot::default()),
                Some(kind) => Err(kind.into()),
            }
        }
    }

    #[test]
    fn conntrack_probe_names_the_proc_source_when_the_proc_read_succeeds() {
        let reader = SystemConntrack::new(FixedRead(None), NOT_CALLED);

        match probe_conntrack(&reader) {
            ConntrackProbe::Found(source) => {
                assert_eq!(source, ConntrackSource::Proc);
                assert_eq!(source.name(), "proc");
            }
            ConntrackProbe::Missing(e) => panic!("expected the proc source, got {e:?}"),
        }
    }

    #[test]
    fn conntrack_probe_reports_missing_with_the_error_when_the_proc_read_fails() {
        let reader = SystemConntrack::new(
            FixedRead(Some(std::io::ErrorKind::PermissionDenied)),
            NOT_CALLED,
        );

        match probe_conntrack(&reader) {
            ConntrackProbe::Missing(e) => {
                assert_eq!(e.proc.kind(), std::io::ErrorKind::PermissionDenied);
            }
            ConntrackProbe::Found(source) => panic!("expected no source, got {source:?}"),
        }
    }

    /// A netlink stand-in for tests where the dump must not be reached. It
    /// fails with a kind no test expects, so reaching it shows in the result.
    const NOT_CALLED: FixedRead = FixedRead(Some(std::io::ErrorKind::Unsupported));

    /// A conntrack querier that reports one session to a fixed address.
    struct OneSession(Ipv6Addr);

    impl ConntrackQuerier for OneSession {
        fn snapshot(&self) -> Result<ConntrackSnapshot, std::io::Error> {
            Ok(ConntrackSnapshot::from_counts(HashMap::from([(self.0, 1)])))
        }
    }

    #[test]
    fn system_conntrack_falls_back_to_netlink_when_the_proc_file_is_absent() {
        let addr: Ipv6Addr = "fd01::1".parse().unwrap();
        let reader = SystemConntrack::new(
            FixedRead(Some(std::io::ErrorKind::NotFound)),
            OneSession(addr),
        );

        let (source, snapshot) = reader.read().expect("the netlink dump answered");

        assert_eq!(source, ConntrackSource::Netlink);
        assert_eq!(source.name(), "netlink");
        assert_eq!(snapshot.sessions_for(addr), 1);
    }

    #[test]
    fn system_conntrack_does_not_fall_back_on_a_proc_error_other_than_not_found() {
        let addr: Ipv6Addr = "fd01::1".parse().unwrap();
        let reader = SystemConntrack::new(
            FixedRead(Some(std::io::ErrorKind::PermissionDenied)),
            OneSession(addr),
        );

        let e = reader
            .read()
            .expect_err("a denied proc read is not a missing file");

        assert_eq!(e.proc.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(e.netlink.is_none(), "netlink was not tried");
        assert_eq!(
            reader.snapshot().unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn system_conntrack_prefers_proc_when_it_reads() {
        let proc_addr: Ipv6Addr = "fd01::1".parse().unwrap();
        let netlink_addr: Ipv6Addr = "fd01::2".parse().unwrap();
        let reader = SystemConntrack::new(OneSession(proc_addr), OneSession(netlink_addr));

        let (source, snapshot) = reader.read().expect("the proc file answered");

        assert_eq!(source, ConntrackSource::Proc);
        assert_eq!(snapshot.sessions_for(proc_addr), 1);
        assert_eq!(snapshot.sessions_for(netlink_addr), 0);
    }

    #[test]
    fn conntrack_probe_reports_both_errors_when_neither_source_reads() {
        let reader = SystemConntrack::new(
            FixedRead(Some(std::io::ErrorKind::NotFound)),
            FixedRead(Some(std::io::ErrorKind::PermissionDenied)),
        );

        match probe_conntrack(&reader) {
            ConntrackProbe::Missing(e) => {
                assert_eq!(e.proc.kind(), std::io::ErrorKind::NotFound);
                assert_eq!(
                    e.netlink.as_ref().map(std::io::Error::kind),
                    Some(std::io::ErrorKind::PermissionDenied)
                );
            }
            ConntrackProbe::Found(source) => panic!("expected no source, got {source:?}"),
        }
        // The per-tick read reports the error that decided it: the dump's.
        assert_eq!(
            reader.snapshot().unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
}
