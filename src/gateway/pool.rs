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
}

impl PoolError {
    /// A short name for the error, for structured log fields.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::AtCeiling(_) => "ceiling",
            Self::RateLimited => "rate-limited",
            Self::Exhausted(_) => "exhausted",
            Self::AwaitingMark => "awaiting-mark",
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
        Ok(ConntrackSnapshot::from_counts(parse_conntrack(&content)))
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

/// Count conntrack lines by the destination addresses they name.
///
/// Every `dst=` value is parsed as an address and compared as an address. The
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
fn parse_conntrack(content: &str) -> HashMap<Ipv6Addr, u32> {
    let mut counts: HashMap<Ipv6Addr, u32> = HashMap::new();
    let mut seen: HashSet<Ipv6Addr> = HashSet::new();

    for line in content.lines() {
        seen.clear();
        for token in line.split_whitespace() {
            let Some(value) = token.strip_prefix("dst=") else {
                continue;
            };
            let Ok(addr) = value.parse::<Ipv6Addr>() else {
                continue;
            };
            seen.insert(addr);
        }
        for addr in &seen {
            *counts.entry(*addr).or_insert(0) += 1;
        }
    }

    counts
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
/// held from the previous run and recovered evidence each wait for. The
/// legitimate load it must exceed is the partial read: both readers return an
/// interrupted dump or a non-atomic proc read as a successful snapshot, so one
/// read can miss a live entry, and three misses in a row would take three
/// interrupted reads that each skip it. It costs an attacker nothing they
/// control, and legitimate users about 30 s more before a removed address is
/// reused. The value is not measured: no rate of interrupted dumps was
/// observed.
pub const MAX_ABSENT_READS: u32 = 3;

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

    /// Release the offsets held from the previous run once their hold has
    /// passed.
    fn release_restart_holds(&mut self, now: Instant) {
        if self.hold_until.is_some_and(|until| now >= until) {
            self.free.append(&mut self.restart_held);
            self.hold_until = None;
        }
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
    pub fn nat_removed(&mut self, _virtual_ip: Ipv6Addr, _mesh_addr: Ipv6Addr) {}

    /// Refresh an existing mapping's TTL clock, never creating one.
    ///
    /// Returns whether a mapping for `node_addr` existed. A query the gateway
    /// answers without an address still says the client is using the name, so
    /// it must keep the mapping alive without minting one. Refreshing a
    /// draining mapping cancels reclamation for the renewed TTL.
    pub fn refresh_if_present(&mut self, node_addr: NodeAddr) -> bool {
        self.refresh_at(node_addr, Instant::now())
    }

    fn refresh_at(&mut self, node_addr: NodeAddr, now: Instant) -> bool {
        match self.mappings.get_mut(&node_addr) {
            Some(mapping) => {
                mapping.last_referenced = now;
                if mapping.state == MappingState::Draining {
                    mapping.state = MappingState::Allocated;
                    mapping.drain_start = None;
                }
                true
            }
            None => false,
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
    /// name already in use keeps resolving when new names are refused.
    pub fn allocate_at(
        &mut self,
        node_addr: NodeAddr,
        mesh_addr: Ipv6Addr,
        dns_name: &str,
        now: Instant,
    ) -> Result<Allocation, PoolError> {
        self.clock = self.clock.max(now);
        self.release_restart_holds(now);

        // Idempotent: return existing mapping, refreshed.
        if self.refresh_at(node_addr, now)
            && let Some(mapping) = self.mappings.get(&node_addr)
        {
            return Ok(self.allocation(mapping.virtual_ip, false));
        }

        // Ceiling first, so a refusal there costs no token and names the
        // ceiling whatever the bucket holds.
        if self.mappings.len() >= self.ceiling {
            return Err(PoolError::AtCeiling(self.mappings.len()));
        }
        self.bucket.refill(now);
        if !self.bucket.has_token() {
            return Err(PoolError::RateLimited);
        }
        if self.marks == MarkMode::Pending {
            return Err(self.refuse(PoolError::AwaitingMark, now));
        }
        let Some((offset, position)) = self.free_from_cursor().next() else {
            return Err(PoolError::Exhausted(self.mappings.len()));
        };
        if self.marks == MarkMode::Enforced
            && self.durable_mark.is_some_and(|mark| position >= mark)
        {
            return Err(self.refuse(PoolError::AwaitingMark, now));
        }
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
        };

        self.mappings.insert(node_addr, mapping);
        self.reverse.insert(virtual_ip, node_addr);

        info!(
            virtual_ip = %virtual_ip,
            mesh_addr = %mesh_addr,
            dns_name = %dns_name,
            "Allocated virtual IP"
        );

        Ok(self.allocation(virtual_ip, true))
    }

    /// The allocation for `virtual_ip`, answered with the configured TTL.
    fn allocation(&self, virtual_ip: Ipv6Addr, is_new: bool) -> Allocation {
        Allocation {
            virtual_ip,
            is_new,
            ttl: u32::try_from(self.ttl_secs).unwrap_or(u32::MAX),
            evicted: None,
        }
    }

    /// Periodic tick — drives state transitions. Returns events for
    /// the NAT and network modules.
    pub fn tick(&mut self, now: Instant, conntrack: &ConntrackSnapshot) -> Vec<PoolEvent> {
        self.clock = self.clock.max(now);
        self.release_restart_holds(now);
        if let Some(refused) = self.refusals.release(now) {
            info!(refused, "Pool accepting new names again");
        }
        let mut events = Vec::new();
        let mut to_free = Vec::new();
        let ttl = std::time::Duration::from_secs(self.ttl_secs);
        let grace = std::time::Duration::from_secs(self.grace_secs);

        for (node_addr, mapping) in &mut self.mappings {
            // One map lookup: the conntrack table was read once, before the
            // pool lock was taken.
            let sessions = conntrack.sessions_for(mapping.virtual_ip);
            mapping.session_count = sessions;

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

        // Free expired mappings
        for node_addr in to_free {
            if let Some(mapping) = self.mappings.remove(&node_addr) {
                self.reverse.remove(&mapping.virtual_ip);
                if let Some(offset) = self.addr_offset(mapping.virtual_ip) {
                    self.free.insert(offset);
                }
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

    /// Session counts a test sets directly, handed to `tick` as the snapshot
    /// the tick task would have read from conntrack.
    #[derive(Default)]
    struct Sessions {
        counts: HashMap<Ipv6Addr, u32>,
    }

    impl Sessions {
        fn new() -> Self {
            Self::default()
        }

        fn set(&mut self, addr: Ipv6Addr, count: u32) {
            self.counts.insert(addr, count);
        }

        fn snapshot(&self) -> ConntrackSnapshot {
            ConntrackSnapshot::from_counts(self.counts.clone())
        }
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
    fn ceiling_refuses_a_new_name_without_a_token_and_keeps_existing_names() {
        let t0 = Instant::now();
        let mut pool = limited_pool(3, 10, 1);
        let mut vips = Vec::new();
        for i in 1..=3u8 {
            vips.push(alloc(&mut pool, i, t0).unwrap().0);
        }
        assert_eq!(pool.bucket.tokens(), 7);

        assert!(
            matches!(alloc(&mut pool, 4, t0), Err(PoolError::AtCeiling(3))),
            "a fourth new name must be refused at a ceiling of 3"
        );
        assert_eq!(
            pool.bucket.tokens(),
            7,
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
        // The bucket empties exactly as the ceiling is reached.
        let mut pool = limited_pool(3, 3, 1);
        for i in 1..=3u8 {
            alloc(&mut pool, i, t0).unwrap();
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
        assert_eq!(pool.free.len(), 255); // returned to pool
    }

    #[test]
    fn dns_renewal_preserves_the_full_ttl_after_draining() {
        let t0 = Instant::now();
        let mut pool = VirtualIpPool::with_limits("fd01::/120", 60, 60, 1, 1, 1).unwrap();
        let ct = ConntrackSnapshot::default();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);
        let (vip, _) = pair(pool.allocate_at(node, mesh, "test.fips", t0).unwrap());

        pool.tick(t0 + Duration::from_secs(61), &ct);
        assert_eq!(pool.mappings[&node].state, MappingState::Draining);

        // Renew just before the old grace period ends, with admission full.
        // The answer reuses the same address and promises another 60s TTL.
        let renewed = t0 + Duration::from_secs(120);
        assert_eq!(
            pair(pool.allocate_at(node, mesh, "test.fips", renewed).unwrap()),
            (vip, false)
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
        let ct = ConntrackSnapshot::default();
        let node = make_node_addr(1);
        pool.allocate_at(
            node,
            make_mesh_addr(1),
            "test.fips",
            now - Duration::from_secs(62),
        )
        .unwrap();
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
            counts.get(&virtual_ip).copied().unwrap_or(0),
            1,
            "the kernel writes the uncompressed form, so matching on the \
             address's compressed Display form counts nothing"
        );

        // Healthy path: a different address in the same pool is not counted.
        let other: Ipv6Addr = "fd01::10".parse().unwrap();
        assert_eq!(counts.get(&other).copied().unwrap_or(0), 0);
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

        assert_eq!(counts.get(&virtual_ip).copied().unwrap_or(0), 1);
    }

    #[test]
    fn conntrack_parse_counts_each_line_that_names_the_address() {
        let content = format!("{KERNEL_LINE}\n{KERNEL_LINE}\n");
        let counts = parse_conntrack(&content);
        let virtual_ip: Ipv6Addr = "fd01::1".parse().unwrap();

        assert_eq!(counts.get(&virtual_ip).copied().unwrap_or(0), 2);
    }

    #[test]
    fn conntrack_parse_skips_a_value_that_is_not_an_ipv6_address() {
        let content = "ipv4     2 tcp      6 431999 ESTABLISHED src=192.0.2.1 \
             dst=192.0.2.2 sport=1 dport=2 mark=0 use=1\n";

        assert!(parse_conntrack(content).is_empty());
    }

    #[test]
    fn conntrack_snapshot_reads_zero_for_an_address_it_did_not_see() {
        let snapshot = ConntrackSnapshot::from_counts(parse_conntrack(KERNEL_LINE));

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
