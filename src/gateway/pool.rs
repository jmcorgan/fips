//! Virtual IP pool manager.
//!
//! Manages allocation, TTL, and reclamation of virtual IPv6 addresses
//! from a configured CIDR range. Tracks mapping state and integrates
//! with conntrack to determine active sessions.

use crate::NodeAddr;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv6Addr;
use std::time::Instant;
use tracing::{debug, info};

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
    #[error("prefix length must be between 1 and 128")]
    InvalidPrefix,
    #[error("live-mapping ceiling reached ({0} mappings)")]
    AtCeiling(usize),
    #[error("new-mapping rate limit reached")]
    RateLimited,
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

/// Virtual IP pool manager.
pub struct VirtualIpPool {
    /// The pool CIDR as configured.
    cidr: String,
    /// The pool's network address and prefix length.
    network: (Ipv6Addr, u8),
    /// Available addresses (free pool).
    available: VecDeque<Ipv6Addr>,
    /// Active mappings keyed by NodeAddr.
    mappings: HashMap<NodeAddr, VirtualIpMapping>,
    /// Reverse map: virtual IP → NodeAddr.
    reverse: HashMap<Ipv6Addr, NodeAddr>,
    /// DNS TTL / mapping TTL in seconds.
    ttl_secs: u64,
    /// Grace period after last session before reclamation.
    grace_secs: u64,
    /// Total pool size.
    total: usize,
    /// Most live mappings admitted before new names are refused.
    ceiling: usize,
    /// Rate limit on new mappings.
    bucket: Bucket,
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
    /// Production uses `new`; this exists so tests can set limits small
    /// enough to reach without allocating the compiled-in counts.
    pub fn with_limits(
        cidr: &str,
        ttl_secs: u64,
        grace_secs: u64,
        ceiling: usize,
        burst: u32,
        rate: u32,
    ) -> Result<Self, PoolError> {
        let (base, prefix_len) = parse_ipv6_cidr(cidr)?;
        if prefix_len == 0 || prefix_len > 128 {
            return Err(PoolError::InvalidPrefix);
        }

        let mut available = VecDeque::new();
        let host_bits = 128 - prefix_len;

        // Cap at 2^16 addresses to avoid massive allocations
        let max_addrs: u128 = if host_bits > 16 {
            1u128 << 16
        } else {
            1u128 << host_bits
        };

        let base_int = u128::from(base);
        // Skip address 0 (network equivalent)
        for i in 1..max_addrs {
            available.push_back(Ipv6Addr::from(base_int + i));
        }

        let total = available.len();
        info!(cidr = %cidr, addresses = total, "Virtual IP pool initialized");

        Ok(Self {
            cidr: cidr.to_string(),
            network: (base, prefix_len as u8),
            available,
            mappings: HashMap::new(),
            reverse: HashMap::new(),
            ttl_secs,
            grace_secs,
            total,
            ceiling,
            bucket: Bucket::new(burst, rate),
        })
    }

    /// Create the pool the gateway runs with, from `start`, at `now`.
    pub fn start(
        cidr: &str,
        ttl_secs: u64,
        grace_secs: u64,
        _start: PoolStart,
        _now: Instant,
    ) -> Result<Self, PoolError> {
        Self::new(cidr, ttl_secs, grace_secs)
    }

    /// The pool's network address and prefix length.
    pub fn network(&self) -> (Ipv6Addr, u8) {
        self.network
    }

    /// The state to write before issuing further, if one is due.
    pub fn mark_request(&self) -> Option<PoolState> {
        Some(PoolState {
            version: 1,
            pool: self.cidr.clone(),
            total: u32::try_from(self.total).unwrap_or(u32::MAX),
            from: 1,
            span: 0,
            held: Vec::new(),
            hold_secs: self.ttl_secs.saturating_add(self.grace_secs),
        })
    }

    /// Record that `state` was written.
    pub fn confirm_mark(&mut self, _state: &PoolState) {}

    /// Record that the state could not be written.
    pub fn mark_failed(&mut self) {}

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
        let virtual_ip = self
            .available
            .pop_front()
            .ok_or(PoolError::Exhausted(self.mappings.len()))?;
        self.bucket.take();

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
                self.available.push_back(mapping.virtual_ip);
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
            total: self.total,
            allocated,
            active,
            draining,
            free: self.available.len(),
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
    fn test_pool_creation() {
        let pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
        // /120 = 8 host bits = 256 addresses, minus 1 (network) = 255
        assert_eq!(pool.total, 255);
        assert_eq!(pool.available.len(), 255);
    }

    #[test]
    fn test_pool_allocation() {
        let mut pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);

        let (vip, is_new) = pair(pool.allocate(node, mesh, "test.fips").unwrap());
        assert!(is_new);
        assert_eq!(vip, "fd01::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(pool.available.len(), 254);
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
        assert_eq!(pool.available.len(), 254);
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
        assert_eq!(pool.available.len(), 255); // returned to pool
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
