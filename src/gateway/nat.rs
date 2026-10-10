//! NAT rule management.
//!
//! Manages nftables DNAT/SNAT rules via the rustables netlink API
//! for translating between virtual IPs and FIPS mesh addresses.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use rustables::expr::{
    Bitwise, Cmp, CmpOp, ConnTrackState, Conntrack, ConntrackKey, Counter, HighLevelPayload,
    IPv6HeaderField, Immediate, Lookup, Masquerade, Meta, MetaType, Nat, NatType,
    NetworkHeaderField, Register, TCPHeaderField, TransportHeaderField, UDPHeaderField,
    VerdictKind,
};
use rustables::set::{SetBuilder, SetElementList};
use rustables::{
    Batch, Chain, ChainType, Hook, HookClass, MsgType, ProtocolFamily, Rule, Set, Table,
};

use crate::config::{PortForward, Proto};

const TABLE_NAME: &str = "fips_gateway";
const PREROUTING_CHAIN: &str = "prerouting";
const POSTROUTING_CHAIN: &str = "postrouting";
const FORWARD_CHAIN: &str = "forward";
const RAW_CHAIN: &str = "raw_prerouting";

/// The set of mapped mesh addresses, which only `fips0` may send from.
const MESH_SOURCE_SET: &str = "fips_mesh_sources";

/// The set's id within a batch, so the rule that looks it up resolves it in
/// the same transaction that creates it.
const MESH_SOURCE_SET_ID: u32 = 1;

/// The mesh TUN interface, as the kernel compares interface names: the name
/// and its terminating NUL. Every interface match on the TUN is built from
/// this one constant.
const TUN_IFACE: &[u8] = b"fips0\0";

/// The loopback interface, as the kernel compares interface names.
const LOOPBACK_IFACE: &[u8] = b"lo\0";

/// NAT priority constants (matching nftables standard priorities).
const DSTNAT_PRIORITY: i32 = -100;
const SRCNAT_PRIORITY: i32 = 100;

/// The standard filter priority, for the forward chain.
const FILTER_PRIORITY: i32 = 0;

/// The raw priority, which runs before connection tracking (-200), so a
/// packet dropped there never reaches a conntrack entry.
const RAW_PRIORITY: i32 = -300;

/// Largest value the kernel accepts for `SO_SNDBUFFORCE`.
///
/// The kernel clamps the requested value to `i32::MAX / 2` and then doubles
/// it, so the socket's send buffer never exceeds `2 * MAX_SNDBUF`.
const MAX_SNDBUF: libc::c_int = libc::c_int::MAX / 2;

/// Headroom added to half the batch length when sizing the send buffer.
const SNDBUF_HEADROOM: u64 = 64 * 1024;

/// The kernel refuses a netlink message longer than the send buffer less
/// this many bytes.
const SNDBUF_OVERHEAD: u64 = 32;

/// How long the rebuild waits for the kernel's acknowledgement. The rebuild
/// runs on the NAT worker thread, so this bounds how long one change can hold
/// up the changes queued behind it.
const ACK_TIMEOUT_SECS: libc::time_t = 5;

/// How long shutdown waits for the NAT table to be deleted: two
/// acknowledgement waits.
pub const NAT_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the NAT worker retries a rebuild the kernel refused.
const RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// Length of a `struct nlmsghdr`.
const NLMSG_HDRLEN: usize = 16;

/// An errno value, displayed by name and number, e.g. `EMSGSIZE (90)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl Errno {
    /// The errno of the last failed libc call on this thread.
    fn last() -> Self {
        Errno(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }

    /// The symbolic name of the errno, for the values netlink can return.
    fn name(self) -> &'static str {
        match self.0 {
            libc::EPERM => "EPERM",
            libc::ENOENT => "ENOENT",
            libc::EINTR => "EINTR",
            libc::EBADF => "EBADF",
            libc::EAGAIN => "EAGAIN",
            libc::ENOMEM => "ENOMEM",
            libc::EACCES => "EACCES",
            libc::EFAULT => "EFAULT",
            libc::EBUSY => "EBUSY",
            libc::EEXIST => "EEXIST",
            libc::ENODEV => "ENODEV",
            libc::EINVAL => "EINVAL",
            libc::ENFILE => "ENFILE",
            libc::EMFILE => "EMFILE",
            libc::ENOSPC => "ENOSPC",
            libc::ERANGE => "ERANGE",
            libc::ELOOP => "ELOOP",
            libc::EMSGSIZE => "EMSGSIZE",
            libc::EPROTONOSUPPORT => "EPROTONOSUPPORT",
            libc::EOPNOTSUPP => "EOPNOTSUPP",
            libc::EAFNOSUPPORT => "EAFNOSUPPORT",
            libc::ENOBUFS => "ENOBUFS",
            libc::ETIMEDOUT => "ETIMEDOUT",
            _ => "errno",
        }
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.0)
    }
}

/// Errors from NAT operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum NatError {
    #[error("nftables error: {0}")]
    Nftables(String),
    #[error("rule not found for virtual IP {0}")]
    RuleNotFound(Ipv6Addr),
    /// The kernel rejected a message of the NAT batch; the batch was aborted.
    #[error("kernel rejected netlink message {seq} of the NAT batch: {errno}")]
    Kernel { errno: Errno, seq: u32 },
    /// A netlink socket call failed.
    #[error("netlink socket {op} failed: {errno}")]
    Socket { op: &'static str, errno: Errno },
    /// The batch is larger than any netlink send buffer the kernel allows.
    #[error(
        "NAT batch of {bytes} bytes exceeds the kernel's netlink limit of {} bytes",
        admissible_limit()
    )]
    BatchTooLarge { bytes: usize },
    /// The NAT worker thread has stopped.
    #[error("the NAT worker has stopped")]
    WorkerStopped,
}

impl NatError {
    /// The failure as the log latches compare it: its text without the parts
    /// that change from batch to batch for one cause, the index of the
    /// rejected message and the batch size.
    fn latch_key(&self) -> String {
        match self {
            Self::Kernel { errno, .. } => {
                format!("kernel rejected a message of the NAT batch: {errno}")
            }
            Self::BatchTooLarge { .. } => {
                "NAT batch exceeds the kernel's netlink limit".to_string()
            }
            other => other.to_string(),
        }
    }
}

impl From<rustables::error::QueryError> for NatError {
    fn from(e: rustables::error::QueryError) -> Self {
        NatError::Nftables(e.to_string())
    }
}

impl From<rustables::error::BuilderError> for NatError {
    fn from(e: rustables::error::BuilderError) -> Self {
        NatError::Nftables(e.to_string())
    }
}

/// A virtual IP ↔ mesh address mapping for NAT rule generation.
#[derive(Clone)]
struct NatMapping {
    virtual_ip: Ipv6Addr,
    mesh_addr: Ipv6Addr,
}

/// One object a NAT rebuild sends, named rather than built.
///
/// `rebuild_batches` decides what a rebuild sends and in what order;
/// `encode_batch` turns that decision into netlink bytes and `send_batch`
/// hands them to the kernel. The split is what lets a test see the delete and the
/// recreate share one transaction without a netlink socket, which is the
/// property that keeps the table in the packet path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NatOp {
    Table(MsgType),
    PreChain,
    PostChain,
    ForwardChain,
    RawChain,
    /// Drop, before connection tracking, traffic to the pool that arrives on
    /// neither the LAN interface nor loopback.
    NonLanPoolDrop,
    /// Drop traffic into `fips0` from any interface but the LAN unless it
    /// belongs to an established or related flow.
    NonLanForwardDrop,
    /// The set of mapped mesh addresses.
    MeshSourceSet,
    /// Its elements, sent only when at least one mapping exists.
    MeshSourceElements,
    /// Drop, before connection tracking, packets from a mapped mesh address
    /// that arrive on neither `fips0` nor loopback.
    ForgedSourceDrop,
    /// Masquerade for LAN traffic leaving through `fips0`.
    FipsMasquerade,
    /// DNAT for the mapping with this virtual IP.
    Dnat(Ipv6Addr),
    /// SNAT for the mapping with this virtual IP.
    Snat(Ipv6Addr),
    /// DNAT for the port forward at this index in `port_forwards`.
    PortForward(usize),
    /// LAN-side masquerade, emitted once when any port forward exists.
    LanMasquerade,
}

/// NAT rule manager using nftables via rustables netlink API.
///
/// Rebuilds the entire nftables table atomically on every change to
/// avoid relying on kernel rule handle tracking (which rustables
/// doesn't expose). The table is small, so this is cheap: the masquerade
/// of LAN traffic into `fips0`, the forward, pool and forged-source drops
/// in their filter chains with the mesh-source set, two rules per mapping
/// (at most 1000), one rule per inbound forward, and one more masquerade
/// when any forward is present.
pub struct NatManager {
    table: Table,
    pre_chain: Chain,
    post_chain: Chain,
    forward_chain: Chain,
    raw_chain: Chain,
    /// LAN interface name. Only traffic arriving on it is translated onto
    /// the mesh, and it gates the port-forward LAN-side masquerade.
    lan_interface: String,
    /// The virtual IP range, as its network address and prefix length.
    pool: (Ipv6Addr, u8),
    /// Active mappings keyed by virtual IP.
    mappings: HashMap<Ipv6Addr, NatMapping>,
    /// Inbound port-forward rules.
    port_forwards: Vec<PortForward>,
    /// Desired state has not yet been acknowledged by the kernel.
    rebuild_pending: bool,
    /// Mappings removed from the desired state whose removal the kernel has
    /// not yet acknowledged, as virtual IP and mesh address.
    unconfirmed: HashSet<(Ipv6Addr, Ipv6Addr)>,
    /// Removals the kernel has acknowledged, or that never had rules, not yet
    /// handed to the caller.
    removed: Vec<(Ipv6Addr, Ipv6Addr)>,
}

impl NatManager {
    /// Build the manager's state without touching netlink.
    ///
    /// Everything `new` does except sending the first rebuild, so a test can
    /// exercise the batch builder with no socket and no privileges.
    fn with_state(lan_interface: String, pool: (Ipv6Addr, u8)) -> Self {
        Self::with_state_in(TABLE_NAME, lan_interface, pool)
    }

    /// `with_state` with the table, and every object in it, under `table_name`.
    fn with_state_in(table_name: &str, lan_interface: String, pool: (Ipv6Addr, u8)) -> Self {
        let table = Table::new(ProtocolFamily::Inet).with_name(table_name);
        let pre_chain = Chain::new(&table)
            .with_name(PREROUTING_CHAIN)
            .with_type(ChainType::Nat)
            .with_hook(Hook::new(HookClass::PreRouting, DSTNAT_PRIORITY));
        let post_chain = Chain::new(&table)
            .with_name(POSTROUTING_CHAIN)
            .with_type(ChainType::Nat)
            .with_hook(Hook::new(HookClass::PostRouting, SRCNAT_PRIORITY));
        let forward_chain = Chain::new(&table)
            .with_name(FORWARD_CHAIN)
            .with_type(ChainType::Filter)
            .with_hook(Hook::new(HookClass::Forward, FILTER_PRIORITY));
        let raw_chain = Chain::new(&table)
            .with_name(RAW_CHAIN)
            .with_type(ChainType::Filter)
            .with_hook(Hook::new(HookClass::PreRouting, RAW_PRIORITY));

        Self {
            table,
            pre_chain,
            post_chain,
            forward_chain,
            raw_chain,
            lan_interface,
            pool,
            mappings: HashMap::new(),
            port_forwards: Vec::new(),
            rebuild_pending: false,
            unconfirmed: HashSet::new(),
            removed: Vec::new(),
        }
    }

    /// Create the nftables table, its NAT chains and its filter chains.
    ///
    /// Installs a masquerade rule for LAN traffic exiting via `fips0` so
    /// that LAN client source addresses are rewritten to the gateway's mesh
    /// address, allowing return traffic to route back through the mesh.
    /// Traffic from any other interface is not translated: the forward chain
    /// drops it on its way into `fips0` unless it is a reply, and the raw
    /// chain drops it before connection tracking when it is addressed to the
    /// pool.
    ///
    /// `lan_interface` is the gateway's LAN-facing interface name. `pool` is
    /// the virtual IP range as its network address and prefix length.
    pub fn new(lan_interface: String, pool: (Ipv6Addr, u8)) -> Result<Self, NatError> {
        let mgr = Self::with_state(lan_interface, pool);
        mgr.rebuild()?;

        info!("Created nftables table '{TABLE_NAME}'");
        Ok(mgr)
    }

    /// Replace the current inbound port-forward rule set and rebuild
    /// the nftables table atomically. Pass an empty slice to clear.
    pub fn set_port_forwards(&mut self, forwards: &[PortForward]) -> Result<(), NatError> {
        self.port_forwards = forwards.to_vec();
        self.rebuild_desired()?;
        info!(
            count = self.port_forwards.len(),
            "Applied inbound port forwards"
        );
        Ok(())
    }

    /// Add DNAT and SNAT rules for a virtual IP ↔ mesh address mapping.
    ///
    /// Tests only: the gateway applies changes through `NatTable::apply`.
    #[cfg(test)]
    pub fn add_mapping(
        &mut self,
        virtual_ip: Ipv6Addr,
        mesh_addr: Ipv6Addr,
    ) -> Result<(), NatError> {
        self.set_mapping(virtual_ip, mesh_addr);
        let (result, elapsed_us) = self.timed_rebuild();
        let mappings = self.mappings.len();
        match &result {
            Ok(()) => debug!(
                virtual_ip = %virtual_ip,
                mesh_addr = %mesh_addr,
                mappings,
                elapsed_us,
                "Added DNAT/SNAT rules"
            ),
            Err(e) => debug!(
                virtual_ip = %virtual_ip,
                mesh_addr = %mesh_addr,
                mappings,
                elapsed_us,
                error = %e,
                "Added DNAT/SNAT rules"
            ),
        }
        result
    }

    /// Remove DNAT and SNAT rules for a virtual IP mapping, whichever mesh
    /// address it holds.
    ///
    /// Tests only: the gateway removes a mapping through `NatTable::apply`,
    /// which removes it only while it still names the expected mesh address.
    #[cfg(test)]
    pub fn remove_mapping(&mut self, virtual_ip: Ipv6Addr) -> Result<(), NatError> {
        let Some(old) = self.mappings.remove(&virtual_ip) else {
            return Err(NatError::RuleNotFound(virtual_ip));
        };
        self.unconfirmed.insert((virtual_ip, old.mesh_addr));
        let (result, elapsed_us) = self.timed_rebuild();
        let mappings = self.mappings.len();
        match &result {
            Ok(()) => debug!(
                virtual_ip = %virtual_ip,
                mappings,
                elapsed_us,
                "Removed DNAT/SNAT rules"
            ),
            Err(e) => debug!(
                virtual_ip = %virtual_ip,
                mappings,
                elapsed_us,
                error = %e,
                "Removed DNAT/SNAT rules"
            ),
        }
        result
    }

    /// Flush all rules and delete the nftables table.
    pub fn cleanup(self) -> Result<(), NatError> {
        let mut batch = Batch::new();
        batch.add(&self.table, MsgType::Del);
        batch
            .send()
            .map_err(|e| NatError::Nftables(error_chain(&e)))?;

        info!("Deleted nftables table '{TABLE_NAME}'");
        Ok(())
    }

    /// Number of active NAT mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// Retry a failed rebuild using the latest desired state.
    ///
    /// Returns whether a pending rebuild was applied. A clean manager does
    /// not open a socket or rebuild the table.
    pub fn retry_pending(&mut self) -> Result<bool, NatError> {
        if !self.rebuild_pending {
            return Ok(false);
        }
        self.rebuild_desired()?;
        Ok(true)
    }

    /// The objects a rebuild sends, grouped into the batches that carry them.
    ///
    /// One batch, always. The kernel applies a batch as a single transaction,
    /// so the table is deleted and recreated without ever leaving the packet
    /// path, and a batch the kernel rejects leaves the previous table in
    /// place. The leading `Add` is what makes the `Del` legal on a first run:
    /// rustables sends a table `Add` with `NLM_F_CREATE` and no `NLM_F_EXCL`,
    /// so it succeeds whether or not the table already exists and the `Del`
    /// that follows always has a target.
    fn rebuild_batches(&self) -> Vec<Vec<NatOp>> {
        let mut ops = vec![
            NatOp::Table(MsgType::Add),
            NatOp::Table(MsgType::Del),
            NatOp::Table(MsgType::Add),
            NatOp::PreChain,
            NatOp::PostChain,
            NatOp::ForwardChain,
            NatOp::RawChain,
            NatOp::MeshSourceSet,
        ];
        if !self.mappings.is_empty() {
            ops.push(NatOp::MeshSourceElements);
        }
        ops.extend([
            NatOp::NonLanPoolDrop,
            NatOp::ForgedSourceDrop,
            NatOp::NonLanForwardDrop,
            NatOp::FipsMasquerade,
        ]);

        // When any port forwards are configured, one LAN-side masquerade in
        // postrouting gives the LAN target the gateway's LAN address as the
        // source, so replies flow back through conntrack. It goes ahead of
        // every per-mapping SNAT: those match on source address alone, NAT
        // statements are terminal, and a SNAT listed first would take an
        // inbound forwarded flow from a peer that holds a live mapping.
        if !self.port_forwards.is_empty() {
            ops.push(NatOp::LanMasquerade);
        }

        for mapping in self.mappings.values() {
            ops.push(NatOp::Dnat(mapping.virtual_ip));
            ops.push(NatOp::Snat(mapping.virtual_ip));
        }

        // Inbound port-forward rules. Each forward is one DNAT rule in
        // prerouting keyed on (iif fips0, nfproto ipv6, l4proto, th dport).
        for index in 0..self.port_forwards.len() {
            ops.push(NatOp::PortForward(index));
        }

        vec![ops]
    }

    /// Build each op into its rustables object and encode the batch.
    ///
    /// Only the last object before the batch end requests an
    /// acknowledgement. rustables sets `NLM_F_ACK` on every message, and one
    /// ack per message overflows the socket's receive buffer from about a
    /// hundred mappings, after the kernel has already committed the batch.
    /// The kernel reports a failing message whatever its flags, so errors
    /// stay attributable.
    fn encode_batch(&self, ops: &[NatOp]) -> Result<Vec<u8>, NatError> {
        let mut batch = Batch::new();
        for op in ops {
            match *op {
                NatOp::Table(msg_type) => batch.add(&self.table, msg_type),
                NatOp::MeshSourceSet => batch.add(&self.mesh_sources()?.0, MsgType::Add),
                NatOp::MeshSourceElements => batch.add(&self.mesh_sources()?.1, MsgType::Add),
                _ => {
                    if let Some(chain) = self.chain_for(*op) {
                        batch.add(chain, MsgType::Add);
                    } else if let Some(rule) = self.rule_for(*op)? {
                        batch.add(&rule, MsgType::Add);
                    }
                }
            }
        }
        let mut bytes = batch.finalize();
        keep_last_ack(&mut bytes)?;
        Ok(bytes)
    }

    /// The chain a chain op adds, or `None` for any other op.
    fn chain_for(&self, op: NatOp) -> Option<&Chain> {
        match op {
            NatOp::PreChain => Some(&self.pre_chain),
            NatOp::PostChain => Some(&self.post_chain),
            NatOp::ForwardChain => Some(&self.forward_chain),
            NatOp::RawChain => Some(&self.raw_chain),
            _ => None,
        }
    }

    /// The rule an op adds, or `None` for an op that adds no rule.
    fn rule_for(&self, op: NatOp) -> Result<Option<Rule>, NatError> {
        match op {
            NatOp::Table(_)
            | NatOp::PreChain
            | NatOp::PostChain
            | NatOp::ForwardChain
            | NatOp::RawChain
            | NatOp::MeshSourceSet
            | NatOp::MeshSourceElements => Ok(None),
            NatOp::ForgedSourceDrop => {
                // A host on the LAN or any other interface could otherwise
                // forge a reply from a mapped node and have conntrack count
                // it as that node's. Only fips0 carries the mesh's traffic.
                // Loopback is exempt: a LAN client may name the gateway's
                // own node, which puts the gateway's own mesh address in the
                // set, and its local connections re-enter on lo.
                let (set, _) = self.mesh_sources()?;
                let rule = Rule::new(&self.raw_chain)?
                    .with_expr(Meta::new(MetaType::NfProto))
                    .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                    .with_expr(Meta::new(MetaType::IifName))
                    .with_expr(Cmp::new(CmpOp::Neq, TUN_IFACE.to_vec()))
                    .with_expr(Meta::new(MetaType::IifName))
                    .with_expr(Cmp::new(CmpOp::Neq, LOOPBACK_IFACE.to_vec()))
                    .with_expr(
                        HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Saddr))
                            .build(),
                    )
                    .with_expr(Lookup::new(&set)?)
                    .with_expr(Counter::default())
                    .with_expr(Immediate::new_verdict(VerdictKind::Drop));
                Ok(Some(rule))
            }
            NatOp::NonLanPoolDrop => {
                // Before conntrack the packet still carries the virtual IP as
                // its destination. Dropping it here keeps a host on another
                // interface from joining a LAN flow by sending in its original
                // direction, which conntrack would translate and forward
                // whatever interface it arrived on. Loopback is exempt, so the
                // gateway's own connections to a pool address still work.
                let (network, prefix) = self.pool;
                let mask = u128::MAX << (128 - u32::from(prefix.min(128)));
                let network = Ipv6Addr::from(u128::from(network) & mask);
                let mask = mask.to_be_bytes();
                let rule = Rule::new(&self.raw_chain)?
                    .with_expr(Meta::new(MetaType::NfProto))
                    .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                    .with_expr(Meta::new(MetaType::IifName))
                    .with_expr(Cmp::new(CmpOp::Neq, self.lan_iface_bytes()))
                    .with_expr(Meta::new(MetaType::IifName))
                    .with_expr(Cmp::new(CmpOp::Neq, LOOPBACK_IFACE.to_vec()))
                    .with_expr(
                        HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Daddr))
                            .build(),
                    )
                    .with_expr(Bitwise::new(mask, [0u8; 16])?)
                    .with_expr(Cmp::new(CmpOp::Eq, network.octets()))
                    .with_expr(Counter::default())
                    .with_expr(Immediate::new_verdict(VerdictKind::Drop));
                Ok(Some(rule))
            }
            NatOp::NonLanForwardDrop => {
                // "Drop unless established or related": new, invalid and
                // untracked packets from other interfaces never reach the
                // mesh under the gateway's identity.
                let allowed = (ConnTrackState::ESTABLISHED | ConnTrackState::RELATED).bits();
                let rule = Rule::new(&self.forward_chain)?
                    .with_expr(Meta::new(MetaType::NfProto))
                    .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                    .with_expr(Meta::new(MetaType::OifName))
                    .with_expr(Cmp::new(CmpOp::Eq, TUN_IFACE.to_vec()))
                    .with_expr(Meta::new(MetaType::IifName))
                    .with_expr(Cmp::new(CmpOp::Neq, self.lan_iface_bytes()))
                    .with_expr(Conntrack::new(ConntrackKey::State))
                    .with_expr(Bitwise::new(allowed.to_ne_bytes(), [0u8; 4])?)
                    .with_expr(Cmp::new(CmpOp::Eq, [0u8; 4]))
                    .with_expr(Counter::default())
                    .with_expr(Immediate::new_verdict(VerdictKind::Drop));
                Ok(Some(rule))
            }
            NatOp::FipsMasquerade => {
                // Rewrite the source address of LAN traffic leaving fips0.
                // Without this, LAN clients' source addresses (e.g.
                // fd02::20) are not routable on the mesh, so return
                // traffic would be black-holed.
                let rule = Rule::new(&self.post_chain)?
                    .with_expr(Meta::new(MetaType::IifName))
                    .with_expr(Cmp::new(CmpOp::Eq, self.lan_iface_bytes()))
                    .with_expr(Meta::new(MetaType::OifName))
                    .with_expr(Cmp::new(CmpOp::Eq, TUN_IFACE.to_vec()))
                    .with_expr(Masquerade::default());
                Ok(Some(rule))
            }
            NatOp::Dnat(virtual_ip) => {
                let mapping = self.mapping(virtual_ip)?;
                let rule = Rule::new(&self.pre_chain)?
                    .with_expr(Meta::new(MetaType::IifName))
                    .with_expr(Cmp::new(CmpOp::Eq, self.lan_iface_bytes()))
                    .with_expr(Meta::new(MetaType::NfProto))
                    .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                    .with_expr(
                        HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Daddr))
                            .build(),
                    )
                    .with_expr(Cmp::new(CmpOp::Eq, mapping.virtual_ip.octets()))
                    .with_expr(Immediate::new_data(
                        mapping.mesh_addr.octets().to_vec(),
                        Register::Reg1,
                    ))
                    .with_expr(
                        Nat::default()
                            .with_nat_type(NatType::DNat)
                            .with_family(ProtocolFamily::Ipv6)
                            .with_ip_register(Register::Reg1),
                    );
                Ok(Some(rule))
            }
            NatOp::Snat(virtual_ip) => {
                let mapping = self.mapping(virtual_ip)?;
                let rule = Rule::new(&self.post_chain)?
                    .with_expr(Meta::new(MetaType::NfProto))
                    .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                    .with_expr(
                        HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Saddr))
                            .build(),
                    )
                    .with_expr(Cmp::new(CmpOp::Eq, mapping.mesh_addr.octets()))
                    .with_expr(Immediate::new_data(
                        mapping.virtual_ip.octets().to_vec(),
                        Register::Reg1,
                    ))
                    .with_expr(
                        Nat::default()
                            .with_nat_type(NatType::SNat)
                            .with_family(ProtocolFamily::Ipv6)
                            .with_ip_register(Register::Reg1),
                    );
                Ok(Some(rule))
            }
            NatOp::PortForward(index) => {
                let pf = self
                    .port_forwards
                    .get(index)
                    .expect("rebuild_batches only emits indices it read from port_forwards");
                let l4proto: u8 = match pf.proto {
                    Proto::Tcp => libc::IPPROTO_TCP as u8,
                    Proto::Udp => libc::IPPROTO_UDP as u8,
                };
                let dport_field = match pf.proto {
                    Proto::Tcp => TransportHeaderField::Tcp(TCPHeaderField::Dport),
                    Proto::Udp => TransportHeaderField::Udp(UDPHeaderField::Dport),
                };
                let target_ip = *pf.target.ip();
                let target_port_be = pf.target.port().to_be_bytes();

                let rule = Rule::new(&self.pre_chain)?
                    .with_expr(Meta::new(MetaType::IifName))
                    .with_expr(Cmp::new(CmpOp::Eq, TUN_IFACE.to_vec()))
                    .with_expr(Meta::new(MetaType::NfProto))
                    .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                    .with_expr(Meta::new(MetaType::L4Proto))
                    .with_expr(Cmp::new(CmpOp::Eq, [l4proto]))
                    .with_expr(HighLevelPayload::Transport(dport_field).build())
                    .with_expr(Cmp::new(CmpOp::Eq, pf.listen_port.to_be_bytes().to_vec()))
                    .with_expr(Immediate::new_data(
                        target_ip.octets().to_vec(),
                        Register::Reg1,
                    ))
                    .with_expr(Immediate::new_data(target_port_be.to_vec(), Register::Reg2))
                    .with_expr(
                        Nat::default()
                            .with_nat_type(NatType::DNat)
                            .with_family(ProtocolFamily::Ipv6)
                            .with_ip_register(Register::Reg1)
                            .with_port_register(Register::Reg2),
                    );
                Ok(Some(rule))
            }
            NatOp::LanMasquerade => {
                let lan_iface = self.lan_iface_bytes();
                let rule = Rule::new(&self.post_chain)?
                    .with_expr(Meta::new(MetaType::IifName))
                    .with_expr(Cmp::new(CmpOp::Eq, TUN_IFACE.to_vec()))
                    .with_expr(Meta::new(MetaType::OifName))
                    .with_expr(Cmp::new(CmpOp::Eq, lan_iface))
                    .with_expr(Meta::new(MetaType::NfProto))
                    .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                    .with_expr(Masquerade::default());
                Ok(Some(rule))
            }
        }
    }

    /// The set of mapped mesh addresses and its element list, each address
    /// once although several virtual IPs may map to it.
    ///
    /// rustables leaves a new set's family unspecified while giving its
    /// element list the table's, and a batch sends each object's own family,
    /// so the set's family is set here or the kernel finds no table for it.
    fn mesh_sources(&self) -> Result<(Set, SetElementList), NatError> {
        let mut builder = SetBuilder::<Ipv6Addr>::new(MESH_SOURCE_SET, &self.table)?;
        let sources: std::collections::BTreeSet<Ipv6Addr> =
            self.mappings.values().map(|m| m.mesh_addr).collect();
        for source in &sources {
            builder.add(source);
        }
        let (mut set, list) = builder.finish();
        set.family = ProtocolFamily::Inet;
        set.set_id(MESH_SOURCE_SET_ID);
        Ok((set, list))
    }

    /// The LAN interface name as the kernel compares it, with its NUL.
    fn lan_iface_bytes(&self) -> Vec<u8> {
        let mut bytes = self.lan_interface.clone().into_bytes();
        bytes.push(0);
        bytes
    }

    /// The mapping an op names, or the error a caller can report.
    fn mapping(&self, virtual_ip: Ipv6Addr) -> Result<&NatMapping, NatError> {
        self.mappings
            .get(&virtual_ip)
            .ok_or(NatError::RuleNotFound(virtual_ip))
    }

    /// Rebuild the entire nftables table with all current rules, in one
    /// netlink transaction.
    fn rebuild(&self) -> Result<(), NatError> {
        for ops in self.rebuild_batches() {
            send_batch(&self.encode_batch(&ops)?)?;
        }
        Ok(())
    }

    /// Rebuild, returning the outcome with the time the rebuild took in
    /// microseconds, so a mapping change can log its cost on either path.
    fn timed_rebuild(&mut self) -> (Result<(), NatError>, u64) {
        let started = Instant::now();
        let result = self.rebuild_desired();
        let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        (result, elapsed_us)
    }

    /// Rebuild the desired state, leaving it marked pending unless the kernel
    /// accepts it.
    fn rebuild_desired(&mut self) -> Result<(), NatError> {
        self.track_rebuild(Self::rebuild)
    }

    /// Run `apply` with the desired state marked pending, and clear the mark
    /// only if it succeeds.
    ///
    /// Split from `rebuild_desired` so a test can drive both outcomes without
    /// a netlink socket.
    fn track_rebuild(
        &mut self,
        apply: impl FnOnce(&Self) -> Result<(), NatError>,
    ) -> Result<(), NatError> {
        self.rebuild_pending = true;
        apply(self)?;
        self.rebuild_pending = false;
        self.confirm_removals();
        Ok(())
    }

    /// After a rebuild the kernel accepted, move every removed pair that the
    /// accepted table no longer holds to the removals reported to the caller.
    fn confirm_removals(&mut self) {
        let mappings = &self.mappings;
        let gone: Vec<(Ipv6Addr, Ipv6Addr)> = self
            .unconfirmed
            .iter()
            .filter(|(virtual_ip, mesh_addr)| {
                mappings.get(virtual_ip).map(|m| m.mesh_addr) != Some(*mesh_addr)
            })
            .copied()
            .collect();
        for pair in gone {
            self.unconfirmed.remove(&pair);
            self.removed.push(pair);
        }
    }

    /// Map `virtual_ip` to `mesh_addr` in the desired state.
    fn set_mapping(&mut self, virtual_ip: Ipv6Addr, mesh_addr: Ipv6Addr) {
        if let Some(old) = self.mappings.insert(
            virtual_ip,
            NatMapping {
                virtual_ip,
                mesh_addr,
            },
        ) && old.mesh_addr != mesh_addr
        {
            self.unconfirmed.insert((virtual_ip, old.mesh_addr));
        }
    }

    /// Apply one `Remove` command to the desired state.
    ///
    /// Only a mapping to the command's mesh address is removed: a removal
    /// queued behind the reissue of its address to another node must not
    /// unmap the new holder. A mapping that is absent has no rules in the
    /// kernel table, so its removal is reported at once, unless an earlier
    /// removal of the same pair is still waiting for the kernel; a pair the
    /// table no longer holds because the address is now another node's is
    /// reported once a rebuild without it has succeeded.
    fn remove_command(
        &mut self,
        virtual_ip: Ipv6Addr,
        mesh_addr: Ipv6Addr,
    ) -> Result<(), NatError> {
        match self.mappings.get(&virtual_ip) {
            None => {
                if !self.unconfirmed.contains(&(virtual_ip, mesh_addr)) {
                    self.removed.push((virtual_ip, mesh_addr));
                }
                Err(NatError::RuleNotFound(virtual_ip))
            }
            Some(current) if current.mesh_addr != mesh_addr => {
                self.unconfirmed.insert((virtual_ip, mesh_addr));
                Err(NatError::RuleNotFound(virtual_ip))
            }
            Some(_) => {
                self.mappings.remove(&virtual_ip);
                self.unconfirmed.insert((virtual_ip, mesh_addr));
                Ok(())
            }
        }
    }
}

/// One change to the NAT table's mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatCommand {
    /// Translate `virtual_ip` to `mesh_addr`.
    Add {
        virtual_ip: Ipv6Addr,
        mesh_addr: Ipv6Addr,
    },
    /// Stop translating `virtual_ip`, which was mapped to `mesh_addr`.
    Remove {
        virtual_ip: Ipv6Addr,
        mesh_addr: Ipv6Addr,
    },
}

/// What applying a list of commands did.
#[derive(Debug, Default)]
pub struct NatApplied {
    /// Each command with its outcome, in the order given.
    pub outcomes: Vec<(NatCommand, Result<(), NatError>)>,
    /// Virtual IP and mesh address pairs whose rules are now gone from the
    /// kernel table.
    pub removed: Vec<(Ipv6Addr, Ipv6Addr)>,
}

/// The NAT table as the driver sees it.
///
/// `NatManager` is the real table; tests substitute fakes.
pub trait NatTable: Send + 'static {
    /// Apply the commands, in order.
    fn apply(&mut self, commands: &[NatCommand]) -> NatApplied;
    /// Retry a rebuild the kernel refused, returning whether one was applied
    /// and the removals it confirmed.
    fn retry_pending(&mut self) -> (Result<bool, NatError>, Vec<(Ipv6Addr, Ipv6Addr)>);
    /// Mappings in the desired state.
    fn mapping_count(&self) -> usize;
    /// Delete the table.
    fn cleanup(self: Box<Self>) -> Result<(), NatError>;
}

impl NatTable for NatManager {
    /// Apply every command to the desired state, then rebuild once.
    fn apply(&mut self, commands: &[NatCommand]) -> NatApplied {
        let staged: Vec<(NatCommand, Result<(), NatError>)> = commands
            .iter()
            .map(|command| {
                let result = match *command {
                    NatCommand::Add {
                        virtual_ip,
                        mesh_addr,
                    } => {
                        self.set_mapping(virtual_ip, mesh_addr);
                        Ok(())
                    }
                    NatCommand::Remove {
                        virtual_ip,
                        mesh_addr,
                    } => self.remove_command(virtual_ip, mesh_addr),
                };
                (*command, result)
            })
            .collect();

        let rebuild = if staged.iter().any(|(_, result)| result.is_ok()) {
            let (result, elapsed_us) = self.timed_rebuild();
            let mappings = self.mappings.len();
            let added = commands.iter().any(|c| matches!(c, NatCommand::Add { .. }));
            let count = commands.len();
            match (&result, added) {
                (Ok(()), true) => debug!(
                    mappings,
                    commands = count,
                    elapsed_us,
                    "Added DNAT/SNAT rules"
                ),
                (Ok(()), false) => debug!(
                    mappings,
                    commands = count,
                    elapsed_us,
                    "Removed DNAT/SNAT rules"
                ),
                (Err(e), true) => debug!(
                    mappings,
                    commands = count,
                    elapsed_us,
                    error = %e,
                    "Added DNAT/SNAT rules"
                ),
                (Err(e), false) => debug!(
                    mappings,
                    commands = count,
                    elapsed_us,
                    error = %e,
                    "Removed DNAT/SNAT rules"
                ),
            }
            result
        } else {
            Ok(())
        };

        NatApplied {
            outcomes: staged
                .into_iter()
                .map(|(command, result)| (command, result.and_then(|()| rebuild.clone())))
                .collect(),
            removed: std::mem::take(&mut self.removed),
        }
    }

    fn retry_pending(&mut self) -> (Result<bool, NatError>, Vec<(Ipv6Addr, Ipv6Addr)>) {
        let result = NatManager::retry_pending(self);
        (result, std::mem::take(&mut self.removed))
    }

    fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    fn cleanup(self: Box<Self>) -> Result<(), NatError> {
        NatManager::cleanup(*self)
    }
}

/// Removals the NAT table has applied, and the end of the driver.
pub struct NatReports {
    /// Virtual IP and mesh address pairs whose rules are gone from the kernel
    /// table, in batches.
    pub removed: crossbeam_channel::Receiver<Vec<(Ipv6Addr, Ipv6Addr)>>,
    /// Resolves when the driver stops applying changes.
    pub exit: tokio::sync::oneshot::Receiver<()>,
}

/// A message to the NAT worker.
enum WorkerMessage {
    Command(NatCommand),
    Stop,
}

/// Applies mapping changes to the NAT table on a thread of its own.
///
/// A rebuild is a netlink round trip that can wait seconds for the kernel,
/// so it never runs on the runtime thread that answers `.fips` queries. The
/// worker drains every queued command into one rebuild, retries a refused
/// rebuild every `RETRY_INTERVAL`, and reports removals the kernel has
/// applied. Its end, by shutdown, panic or a dropped driver, resolves
/// `NatReports::exit`.
pub struct NatDriver {
    commands: crossbeam_channel::Sender<WorkerMessage>,
    stopped: crossbeam_channel::Receiver<Result<(), NatError>>,
    count: Arc<AtomicUsize>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl NatDriver {
    /// Take ownership of `table` and start applying changes to it.
    ///
    /// When the worker thread cannot be started, the exit report resolves at
    /// once and every submit fails, so the gateway stops rather than answer
    /// with addresses that have no rules.
    pub fn start(table: Box<dyn NatTable>) -> (NatDriver, NatReports) {
        let (commands_tx, commands_rx) = crossbeam_channel::unbounded();
        let (removed_tx, removed_rx) = crossbeam_channel::unbounded();
        let (stopped_tx, stopped_rx) = crossbeam_channel::bounded(1);
        let (exit_tx, exit_rx) = tokio::sync::oneshot::channel();
        let count = Arc::new(AtomicUsize::new(table.mapping_count()));
        let worker_count = Arc::clone(&count);
        let spawned = std::thread::Builder::new()
            .name("fips-gw-nat".to_string())
            .spawn(move || {
                // Dropped when the loop ends, by return or by panic.
                let _exit = exit_tx;
                run_worker(table, commands_rx, removed_tx, stopped_tx, worker_count);
            });
        let worker = match spawned {
            Ok(handle) => Some(handle),
            Err(e) => {
                error!(error = %e, "Failed to start the NAT worker thread");
                None
            }
        };
        (
            NatDriver {
                commands: commands_tx,
                stopped: stopped_rx,
                count,
                worker,
            },
            NatReports {
                removed: removed_rx,
                exit: exit_rx,
            },
        )
    }

    /// Queue one change.
    pub fn submit(&mut self, command: NatCommand) -> Result<(), NatError> {
        self.commands
            .send(WorkerMessage::Command(command))
            .map_err(|_| NatError::WorkerStopped)
    }

    /// Mappings in the table's desired state, as of the last applied batch.
    pub fn mapping_count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// The count `mapping_count` reads, for a task that has no driver.
    pub fn mapping_counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.count)
    }

    /// Stop applying changes and delete the table, waiting at most `timeout`.
    ///
    /// On timeout the worker is left behind: the next start's rebuild
    /// replaces the table whatever state it is in.
    pub fn shutdown(mut self, timeout: Duration) -> Result<(), NatError> {
        if self.commands.send(WorkerMessage::Stop).is_err() {
            return Err(NatError::WorkerStopped);
        }
        match self.stopped.recv_timeout(timeout) {
            Ok(result) => {
                if let Some(worker) = self.worker.take() {
                    let _ = worker.join();
                }
                result
            }
            Err(_) => {
                warn!(
                    timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                    "NAT worker did not finish deleting the table in time"
                );
                Ok(())
            }
        }
    }
}

/// The NAT worker's loop: apply queued changes in one rebuild, retry a
/// refused rebuild on an interval, and delete the table on `Stop`.
fn run_worker(
    mut table: Box<dyn NatTable>,
    commands: crossbeam_channel::Receiver<WorkerMessage>,
    removed: crossbeam_channel::Sender<Vec<(Ipv6Addr, Ipv6Addr)>>,
    stopped: crossbeam_channel::Sender<Result<(), NatError>>,
    count: Arc<AtomicUsize>,
) {
    let mut retry_log = RetryLog::default();
    let mut apply_log = RetryLog::default();
    let mut next_retry = Instant::now() + RETRY_INTERVAL;
    let publish = |table: &dyn NatTable, report: Vec<(Ipv6Addr, Ipv6Addr)>| {
        count.store(table.mapping_count(), Ordering::Relaxed);
        if !report.is_empty() {
            // Nobody listening is not an error: the reports are advisory.
            let _ = removed.send(report);
        }
    };
    loop {
        let wait = next_retry.saturating_duration_since(Instant::now());
        match commands.recv_timeout(wait) {
            Ok(WorkerMessage::Command(first)) => {
                let mut batch = vec![first];
                let mut stop = false;
                for message in commands.try_iter() {
                    match message {
                        WorkerMessage::Command(command) => batch.push(command),
                        WorkerMessage::Stop => {
                            stop = true;
                            break;
                        }
                    }
                }
                let applied = table.apply(&batch);
                report_apply(&mut apply_log, &batch, &applied);
                publish(table.as_ref(), applied.removed);
                if stop {
                    let _ = stopped.send(table.cleanup());
                    return;
                }
            }
            Ok(WorkerMessage::Stop) => {
                let _ = stopped.send(table.cleanup());
                return;
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                let (result, report) = table.retry_pending();
                report_nat_retry(&mut retry_log, &result);
                publish(table.as_ref(), report);
                next_retry = Instant::now() + RETRY_INTERVAL;
            }
            // The driver was dropped without a shutdown: leave the table.
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// Log a batch's outcome once per change of outcome, and return how it
/// compares with the batch before it.
///
/// Every added mapping comes from a LAN host naming a new name, so under a
/// netlink failure that does not clear a line per batch would be a line per
/// attacker input. The first failure, or a changed one, logs at `error!`
/// when the batch adds a mapping and at `warn!` when it only removes; repeats
/// log at `debug!` with the same text; the first success after a failure
/// logs once. A remove of a mapping that is absent or now another node's is
/// not a failure, and a batch made only of such removes rebuilt nothing, so
/// it leaves the outcome as it was.
pub fn report_apply(
    log: &mut RetryLog,
    commands: &[NatCommand],
    applied: &NatApplied,
) -> RetryReport {
    let failure = applied
        .outcomes
        .iter()
        .find_map(|(_, result)| match result {
            Err(NatError::RuleNotFound(_)) | Ok(()) => None,
            Err(e) => Some(e),
        });
    for (command, result) in &applied.outcomes {
        if let Err(e) = result {
            debug!(?command, error = %e, "NAT command not applied");
        }
    }
    let adds = commands
        .iter()
        .filter(|c| matches!(c, NatCommand::Add { .. }))
        .count();
    let removes = commands.len() - adds;
    let rebuilt = applied
        .outcomes
        .iter()
        .any(|(_, result)| !matches!(result, Err(NatError::RuleNotFound(_))));
    if !rebuilt {
        return log.unchanged();
    }
    let report = log.observe(failure);
    match (report, failure) {
        (RetryReport::Failed, Some(e)) if adds > 0 => {
            error!(error = %e, adds, removes, "Failed to add NAT rules")
        }
        (RetryReport::Failed, Some(e)) => {
            warn!(error = %e, removes, "Failed to remove NAT rules")
        }
        (RetryReport::Repeated, Some(e)) if adds > 0 => {
            debug!(error = %e, adds, removes, "Failed to add NAT rules")
        }
        (RetryReport::Repeated, Some(e)) => {
            debug!(error = %e, removes, "Failed to remove NAT rules")
        }
        (RetryReport::Recovered, _) => info!("NAT rules applied again after failures"),
        _ => {}
    }
    report
}

/// Log a pending NAT rebuild retry once per change of outcome.
///
/// A recovery is reported whether the retry applied the rules itself or a
/// mapping change applied them in between and left nothing pending.
pub fn report_nat_retry(log: &mut RetryLog, result: &Result<bool, NatError>) {
    match (log.observe(result.as_ref().err()), result) {
        (RetryReport::Failed, Err(e)) => {
            warn!(error = %e, "Failed to retry pending NAT rules")
        }
        (RetryReport::Repeated, Err(e)) => {
            debug!(error = %e, "Pending NAT rules still failing to apply")
        }
        (RetryReport::Recovered, Ok(true)) => {
            info!("Applied pending NAT rules; retries recovered")
        }
        (RetryReport::Recovered, _) => {
            info!("Pending NAT rules were applied by a later update; retries recovered")
        }
        (RetryReport::Clean, Ok(true)) => info!("Applied pending NAT rules"),
        _ => {}
    }
}

/// How a pending-rebuild retry compares with the retry before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryReport {
    /// A failure that differs from the previous retry's outcome, or the first.
    Failed,
    /// The same failure as the previous retry.
    Repeated,
    /// The first success after a failed retry.
    Recovered,
    /// A success with no failed retry before it.
    Clean,
}

/// Remembers the last failed retry of a pending rebuild.
///
/// A failure that does not clear on its own, for example the kernel refusing
/// the batch while a module or capability is missing, fails every retry the
/// same way, and a per-retry warning would repeat for the life of the
/// process. Warning on a change of outcome, and reporting the recovery once,
/// keeps the log readable. A retry that finds nothing pending after a failure
/// counts as recovery, since a mapping change rebuilt the table in between.
#[derive(Debug, Default)]
pub struct RetryLog {
    last_failure: Option<String>,
}

impl RetryLog {
    /// Record a retry outcome and say how it compares with the last one.
    ///
    /// `None` is a success, whether or not anything was pending; `Some` is
    /// the retry's error. Two failures are the same when their messages are,
    /// leaving out the message index and batch size, which change with the
    /// batch while the cause does not.
    pub fn observe(&mut self, failure: Option<&NatError>) -> RetryReport {
        self.observe_message(failure.map(NatError::latch_key))
    }

    /// The outcome as it stands, for an operation that learned nothing new:
    /// `Repeated` while a failure is latched, otherwise `Clean`.
    pub fn unchanged(&self) -> RetryReport {
        if self.last_failure.is_some() {
            RetryReport::Repeated
        } else {
            RetryReport::Clean
        }
    }

    /// `observe` for a failure already rendered as text, so other repeated
    /// operations can share the comparison.
    pub fn observe_message(&mut self, failure: Option<String>) -> RetryReport {
        match (failure, self.last_failure.take()) {
            (Some(now), Some(before)) => {
                let report = if now == before {
                    RetryReport::Repeated
                } else {
                    RetryReport::Failed
                };
                self.last_failure = Some(now);
                report
            }
            (Some(now), None) => {
                self.last_failure = Some(now);
                RetryReport::Failed
            }
            (None, Some(_)) => RetryReport::Recovered,
            (None, None) => RetryReport::Clean,
        }
    }
}

/// Largest batch, in bytes, that the kernel can admit in one send.
fn admissible_limit() -> u64 {
    2 * MAX_SNDBUF as u64 - SNDBUF_OVERHEAD
}

/// The `SO_SNDBUFFORCE` value that lets a batch of `len` bytes through.
///
/// The kernel doubles the value it is given and refuses a message longer
/// than the result less 32 bytes, so half the length plus headroom is
/// enough. Saturates at the kernel's own clamp rather than wrapping.
fn sndbuf_for(len: usize) -> libc::c_int {
    let want = (u64::try_from(len).unwrap_or(u64::MAX) / 2).saturating_add(SNDBUF_HEADROOM);
    libc::c_int::try_from(want.min(MAX_SNDBUF as u64)).unwrap_or(MAX_SNDBUF)
}

/// Refuse a batch the kernel could not accept at any send-buffer size.
fn check_admissible(len: usize) -> Result<(), NatError> {
    if u64::try_from(len).unwrap_or(u64::MAX) > admissible_limit() {
        return Err(NatError::BatchTooLarge { bytes: len });
    }
    Ok(())
}

/// The fields of one `struct nlmsghdr` that the NAT batch code reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NlHeader {
    /// Offset of the header within the buffer.
    offset: usize,
    /// `nlmsg_len`: header plus payload, without alignment padding.
    len: usize,
    kind: u16,
    flags: u16,
    seq: u32,
}

impl NlHeader {
    /// The message's payload, after the header.
    fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.offset + NLMSG_HDRLEN..self.offset + self.len]
    }
}

/// Walk every netlink message header in `buf`.
///
/// Fails on a header shorter than `struct nlmsghdr` or a length that runs
/// past the end of the buffer.
fn nl_headers(buf: &[u8]) -> Result<Vec<NlHeader>, NatError> {
    let mut headers = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        let rest = &buf[offset..];
        if rest.len() < NLMSG_HDRLEN {
            return Err(NatError::Nftables(format!(
                "malformed netlink message at offset {offset}: {} bytes left, header needs {NLMSG_HDRLEN}",
                rest.len()
            )));
        }
        let field = |at: usize, width: usize| &rest[at..at + width];
        let len = u32::from_ne_bytes(field(0, 4).try_into().expect("4-byte slice")) as usize;
        if len < NLMSG_HDRLEN || len > rest.len() {
            return Err(NatError::Nftables(format!(
                "malformed netlink message at offset {offset}: length {len} with {} bytes left",
                rest.len()
            )));
        }
        headers.push(NlHeader {
            offset,
            len,
            kind: u16::from_ne_bytes(field(4, 2).try_into().expect("2-byte slice")),
            flags: u16::from_ne_bytes(field(6, 2).try_into().expect("2-byte slice")),
            seq: u32::from_ne_bytes(field(8, 4).try_into().expect("4-byte slice")),
        });
        // Netlink messages are 4-byte aligned.
        offset += (len + 3) & !3;
    }
    Ok(headers)
}

/// The finalized batch's objects: every message between the batch begin
/// and the batch end.
fn batch_objects(headers: &[NlHeader]) -> Result<&[NlHeader], NatError> {
    match headers {
        [_begin, objects @ .., _end] if !objects.is_empty() => Ok(objects),
        _ => Err(NatError::Nftables(format!(
            "NAT batch holds {} messages; it needs a begin, an object and an end",
            headers.len()
        ))),
    }
}

/// Clear `NLM_F_ACK` on every message of a finalized batch except the last
/// object before the batch end.
fn keep_last_ack(buf: &mut [u8]) -> Result<(), NatError> {
    let headers = nl_headers(buf)?;
    let last = batch_objects(&headers)?
        .last()
        .expect("batch_objects returns a non-empty slice")
        .offset;
    let ack = libc::NLM_F_ACK as u16;
    for header in &headers {
        let flags = if header.offset == last {
            header.flags | ack
        } else {
            header.flags & !ack
        };
        buf[header.offset + 6..header.offset + 8].copy_from_slice(&flags.to_ne_bytes());
    }
    Ok(())
}

/// What the kernel's replies to a NAT batch have shown so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckState {
    /// No verdict yet; read another datagram.
    Pending,
    /// The acknowledgement of the batch's last object arrived with no error
    /// before it.
    Done,
}

/// Reads the kernel's replies to a NAT batch, one datagram at a time.
///
/// The kernel aborts the whole batch when any message fails, yet it still
/// acknowledges the last message after the error. So the last ack alone does
/// not prove success: any error that arrives before it fails the batch.
struct AckReader {
    /// Sequence number of the one message that requested an ack.
    last_seq: u32,
}

impl AckReader {
    /// Consume one received datagram, which may carry several messages.
    fn feed(&self, datagram: &[u8]) -> Result<AckState, NatError> {
        for header in nl_headers(datagram)? {
            if i32::from(header.kind) != libc::NLMSG_ERROR {
                continue;
            }
            let payload = header.payload(datagram);
            if payload.len() < 4 {
                return Err(NatError::Nftables(format!(
                    "malformed netlink error message: {} payload bytes, error field needs 4",
                    payload.len()
                )));
            }
            let error = i32::from_ne_bytes(payload[..4].try_into().expect("4-byte slice"));
            if error != 0 {
                return Err(NatError::Kernel {
                    errno: Errno(error.saturating_neg()),
                    seq: header.seq,
                });
            }
            if header.seq == self.last_seq {
                return Ok(AckState::Done);
            }
        }
        Ok(AckState::Pending)
    }
}

/// Render an error with every source beneath it, so a wrapped errno is kept.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(inner) = source {
        text.push_str(": ");
        text.push_str(&inner.to_string());
        source = inner.source();
    }
    text
}

/// Set an integer socket option.
fn set_int_opt(
    sock: &OwnedFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> Result<(), Errno> {
    // SAFETY: the descriptor is open for the life of `sock`, and the pointer
    // and length describe `value`, a c_int.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            name,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 { Err(Errno::last()) } else { Ok(()) }
}

/// Size of the buffer each reply datagram is read into.
///
/// The largest message nftables sends back, as rustables computes it
/// (`nft_nlmsg_maxsize`, which it does not export), and at least 64 KiB.
fn recv_buffer_len() -> usize {
    // SAFETY: sysconf has no preconditions.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    (usize::from(u16::MAX) + usize::try_from(page).unwrap_or(0)).max(64 * 1024)
}

/// Open a netfilter netlink socket sized for a batch of `len` bytes.
fn open_batch_socket(len: usize) -> Result<OwnedFd, NatError> {
    let socket_err = |op| move |errno| NatError::Socket { op, errno };

    // SAFETY: socket has no memory preconditions.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_NETFILTER,
        )
    };
    if fd < 0 {
        return Err(socket_err("open")(Errno::last()));
    }
    // SAFETY: socket returned a new descriptor that nothing else owns.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };

    // SAFETY: an all-zero sockaddr_nl is valid; the family is set below.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: the pointer and length describe `addr`, a sockaddr_nl.
    let rc = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            (&addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(socket_err("bind")(Errno::last()));
    }

    // Without CAP_NET_ADMIN the forced size is refused; the plain option is
    // then capped by wmem_max, and an oversized batch fails with EMSGSIZE.
    let sndbuf = sndbuf_for(len);
    match set_int_opt(&sock, libc::SOL_SOCKET, libc::SO_SNDBUFFORCE, sndbuf) {
        Err(Errno(libc::EPERM)) => {
            set_int_opt(&sock, libc::SOL_SOCKET, libc::SO_SNDBUF, sndbuf)
                .map_err(socket_err("setsockopt SO_SNDBUF"))?;
        }
        other => other.map_err(socket_err("setsockopt SO_SNDBUFFORCE"))?,
    }
    // An error ack then carries only the failing header, not the message.
    set_int_opt(&sock, libc::SOL_NETLINK, libc::NETLINK_CAP_ACK, 1)
        .map_err(socket_err("setsockopt NETLINK_CAP_ACK"))?;

    let timeout = libc::timeval {
        tv_sec: ACK_TIMEOUT_SECS,
        tv_usec: 0,
    };
    // SAFETY: the pointer and length describe `timeout`, a timeval.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(socket_err("setsockopt SO_RCVTIMEO")(Errno::last()));
    }
    Ok(sock)
}

/// Send one encoded NAT batch and wait for the kernel's verdict.
///
/// The batch goes out in a single send, so the kernel applies it as one
/// transaction. The send buffer is sized to the batch, because the default
/// one refuses a message past about 208 KiB, which is about 313 mappings.
fn send_batch(bytes: &[u8]) -> Result<(), NatError> {
    check_admissible(bytes.len())?;
    let headers = nl_headers(bytes)?;
    let reader = AckReader {
        last_seq: batch_objects(&headers)?
            .last()
            .expect("batch_objects returns a non-empty slice")
            .seq,
    };
    let sock = open_batch_socket(bytes.len())?;

    let sent = loop {
        // SAFETY: the pointer and length describe `bytes`.
        let rc = unsafe { libc::send(sock.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), 0) };
        if rc >= 0 {
            break rc as usize;
        }
        let errno = Errno::last();
        if errno.0 != libc::EINTR {
            return Err(NatError::Socket { op: "send", errno });
        }
    };
    if sent != bytes.len() {
        return Err(NatError::Nftables(format!(
            "netlink send took {sent} of {} bytes",
            bytes.len()
        )));
    }

    let mut buf = vec![0u8; recv_buffer_len()];
    loop {
        // MSG_TRUNC makes a netlink recv return the datagram's full length,
        // so a reply larger than the buffer is detected rather than cut.
        // SAFETY: the pointer and length describe `buf`.
        let rc = unsafe {
            libc::recv(
                sock.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_TRUNC,
            )
        };
        if rc < 0 {
            let errno = Errno::last();
            if errno.0 == libc::EINTR {
                continue;
            }
            // EAGAIN is the receive timeout. ENOBUFS means error acks
            // overflowed the receive buffer, since only one ack is requested.
            return Err(NatError::Socket { op: "recv", errno });
        }
        let got = rc as usize;
        if got == 0 {
            return Err(NatError::Nftables(
                "netlink socket returned no reply".into(),
            ));
        }
        if got > buf.len() {
            return Err(NatError::Nftables(format!(
                "netlink reply of {got} bytes truncated to {}",
                buf.len()
            )));
        }
        if reader.feed(&buf[..got])? == AckState::Done {
            return Ok(());
        }
    }
}

// Coverage gap. These tests run unprivileged and open no netlink socket, so
// three failure paths in `open_socket` and `send_batch` go unexercised here.
// The receive timeout firing and a reply longer than the buffer (seen through
// `MSG_TRUNC`) need a kernel fault to provoke, so nothing runs them. The
// `SO_SNDBUF` fallback after `SO_SNDBUFFORCE` returns `EPERM` needs a process
// without CAP_NET_ADMIN, and the gateway suite's container is privileged, so
// nothing runs that either. The gateway suite covers only the success path.
//
// The pending-rebuild flag is covered here on both sides through
// `track_rebuild`, with a stand-in for the rebuild: a failure leaves it set and
// `retry_pending` still retries, and a success clears it so `retry_pending`
// finds nothing to do. What stays only in the ignored kernel test, which no
// suite runs, is `retry_pending` itself applying a pending rebuild and
// returning `Ok(true)`, and a kernel rejection leaving the old table in place.
#[cfg(test)]
mod tests {
    use super::*;
    use rustables::expr::ExpressionVariant;
    use std::net::SocketAddrV6;

    fn vip(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, last)
    }

    fn mesh(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfd02, 0, 0, 0, 0, 0, 0, last)
    }

    /// The pool the test managers are built with.
    const TEST_POOL: (Ipv6Addr, u8) = (Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 0), 112);

    /// A manager holding `count` mappings and no netlink socket.
    fn manager_with_mappings(count: u16) -> NatManager {
        manager_with_mappings_in(TABLE_NAME, count)
    }

    /// `manager_with_mappings` with every object under `table_name`.
    fn manager_with_mappings_in(table_name: &str, count: u16) -> NatManager {
        let mut mgr = NatManager::with_state_in(table_name, "br-lan".to_string(), TEST_POOL);
        for i in 1..=count {
            mgr.mappings.insert(
                vip(i),
                NatMapping {
                    virtual_ip: vip(i),
                    mesh_addr: mesh(i),
                },
            );
        }
        mgr
    }

    #[test]
    fn failed_rebuild_retains_latest_desired_state_for_retry() {
        let mut mgr = manager_with_mappings(2);
        // Make encoding fail before opening a socket.
        mgr.pre_chain = Chain::new(&mgr.table);
        assert!(!mgr.retry_pending().unwrap(), "clean retry must not encode");

        assert!(mgr.add_mapping(vip(3), mesh(3)).is_err());
        assert!(mgr.rebuild_pending);
        assert!(mgr.retry_pending().is_err());
        assert!(mgr.rebuild_pending);
        assert!(mgr.remove_mapping(vip(3)).is_err());
        assert!(!mgr.mappings.contains_key(&vip(3)));
        assert!(mgr.add_mapping(vip(2), mesh(99)).is_err());
        assert_eq!(mgr.mappings[&vip(2)].mesh_addr, mesh(99));
        assert!(mgr.remove_mapping(vip(4)).is_err());
        assert!(
            mgr.rebuild_pending,
            "an absent mapping must not clear pending work"
        );
    }

    #[test]
    fn failed_tracked_rebuild_stays_pending_and_retry_still_rebuilds() {
        let mut mgr = manager_with_mappings(1);
        let refused = || NatError::Nftables("refused".into());

        assert!(mgr.track_rebuild(|_| Err(refused())).is_err());
        assert!(mgr.rebuild_pending, "a failed rebuild must stay pending");

        // With encoding made to fail, a retry that is still pending attempts
        // the rebuild, and fails, instead of reporting nothing to do.
        mgr.pre_chain = Chain::new(&mgr.table);
        assert!(mgr.retry_pending().is_err());
        assert!(mgr.rebuild_pending);
    }

    #[test]
    fn successful_tracked_rebuild_clears_pending_and_retry_does_nothing() {
        let mut mgr = manager_with_mappings(1);
        assert!(
            mgr.track_rebuild(|_| Err(NatError::Nftables("refused".into())))
                .is_err()
        );
        assert!(mgr.rebuild_pending);

        let mut applied = 0;
        mgr.track_rebuild(|m| {
            assert!(m.rebuild_pending, "the rebuild runs with the mark set");
            applied += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(applied, 1);
        assert!(
            !mgr.rebuild_pending,
            "a successful rebuild must clear pending"
        );

        // Encoding would fail, so `Ok(false)` shows the retry did not rebuild.
        mgr.pre_chain = Chain::new(&mgr.table);
        assert!(!mgr.retry_pending().unwrap());
    }

    #[test]
    fn retry_log_warns_on_a_new_failure_and_reports_recovery_once() {
        let kernel = |errno| NatError::Kernel {
            errno: Errno(errno),
            seq: 3,
        };
        let mut log = RetryLog::default();

        assert_eq!(log.observe(None), RetryReport::Clean);
        assert_eq!(log.observe(Some(&kernel(22))), RetryReport::Failed);
        assert_eq!(log.observe(Some(&kernel(22))), RetryReport::Repeated);
        assert_eq!(log.observe(Some(&kernel(22))), RetryReport::Repeated);
        assert_eq!(
            log.observe(Some(&kernel(1))),
            RetryReport::Failed,
            "a different failure is a different outcome and is worth a line"
        );
        assert_eq!(log.observe(None), RetryReport::Recovered);
        assert_eq!(log.observe(None), RetryReport::Clean);
        assert_eq!(
            log.observe(Some(&kernel(1))),
            RetryReport::Failed,
            "a failure after recovery warns again"
        );
    }

    #[test]
    fn failures_differing_only_in_message_index_or_size_count_as_the_same_failure() {
        let kernel = |errno, seq| NatError::Kernel {
            errno: Errno(errno),
            seq,
        };
        let mut log = RetryLog::default();
        assert_eq!(log.observe(Some(&kernel(2, 3))), RetryReport::Failed);
        assert_eq!(
            log.observe(Some(&kernel(2, 9))),
            RetryReport::Repeated,
            "the same rejection at another message index read as a new failure"
        );
        assert_eq!(
            log.observe(Some(&kernel(1, 9))),
            RetryReport::Failed,
            "control: a different errno is a new failure"
        );

        let mut log = RetryLog::default();
        let large = |bytes| NatError::BatchTooLarge { bytes };
        assert_eq!(log.observe(Some(&large(300_000))), RetryReport::Failed);
        assert_eq!(
            log.observe(Some(&large(300_100))),
            RetryReport::Repeated,
            "an oversized batch of another size read as a new failure"
        );
    }

    #[test]
    fn the_pool_drop_matches_a_pool_configured_with_host_bits_set() {
        let pool = crate::gateway::pool::VirtualIpPool::with_limits("fd01::1/112", 60, 60, 1, 1, 1)
            .expect("the pool accepts the CIDR");
        for network in [pool.network(), ("fd01::1".parse().unwrap(), 112)] {
            let mgr = NatManager::with_state("br-lan".to_string(), network);
            let rule = mgr
                .rule_for(NatOp::NonLanPoolDrop)
                .unwrap()
                .expect("the pool drop is emitted");
            let prefix = Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 0);
            assert!(
                has_in_order(
                    &rule,
                    &[ExpressionVariant::from(Cmp::new(
                        CmpOp::Eq,
                        prefix.octets()
                    ))]
                ),
                "the pool drop given {network:?} does not compare the masked destination with fd01::"
            );
        }
    }

    #[test]
    fn failed_port_forward_rebuild_remains_pending() {
        let mut mgr = manager_with_mappings(1);
        mgr.pre_chain = Chain::new(&mgr.table);
        let forward = PortForward {
            proto: Proto::Tcp,
            listen_port: 8080,
            target: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0),
        };
        assert!(mgr.set_port_forwards(&[forward]).is_err());
        assert_eq!(mgr.port_forwards.len(), 1);
        assert!(mgr.rebuild_pending);
        assert!(mgr.set_port_forwards(&[]).is_err());
        assert!(mgr.port_forwards.is_empty());
        assert!(mgr.rebuild_pending);
    }

    #[test]
    #[ignore = "requires CAP_NET_ADMIN and nft in an isolated network namespace"]
    fn kernel_rejection_retries_latest_state_without_another_mapping_event() {
        let table_name = format!("{TABLE_NAME}_retry_test_{}", std::process::id());
        let mut mgr = manager_with_mappings_in(&table_name, 2);
        mgr.rebuild().unwrap();
        let listing = || {
            let output = std::process::Command::new("nft")
                .args(["-j", "list", "table", "inet", &table_name])
                .output()
                .unwrap();
            assert!(output.status.success());
            output.stdout
        };
        let before = listing();
        // Encoding succeeds, but the kernel rejects an overlong chain name.
        let invalid = Chain::new(&mgr.table).with_name("x".repeat(300));
        let original = std::mem::replace(&mut mgr.pre_chain, invalid);
        assert!(matches!(
            mgr.add_mapping(vip(3), mesh(3)),
            Err(NatError::Kernel { .. })
        ));
        assert!(mgr.remove_mapping(vip(1)).is_err());
        assert!(mgr.remove_mapping(vip(3)).is_err());
        assert!(mgr.add_mapping(vip(2), mesh(99)).is_err());
        assert!(mgr.retry_pending().is_err());
        assert_eq!(
            listing(),
            before,
            "rejection leaves the old kernel table intact"
        );

        mgr.pre_chain = original;
        assert!(mgr.retry_pending().unwrap());
        assert!(!mgr.retry_pending().unwrap());
        assert_eq!(mgr.mapping_count(), 1);
        assert_eq!(mgr.mappings[&vip(2)].mesh_addr, mesh(99));
        let after = listing();
        assert_ne!(after, before);
        let table: serde_json::Value = serde_json::from_slice(&after).unwrap();
        assert_eq!(
            table["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|entry| entry.get("rule").is_some())
                .count(),
            emitted_rules(&mgr).len()
        );
        assert!(String::from_utf8(after).unwrap().contains("fd02::63"));

        // A successful normal update also clears earlier pending work.
        mgr.pre_chain = Chain::new(&mgr.table);
        assert!(mgr.add_mapping(vip(4), mesh(4)).is_err());
        mgr.pre_chain = Chain::new(&mgr.table)
            .with_name(PREROUTING_CHAIN)
            .with_type(ChainType::Nat)
            .with_hook(Hook::new(HookClass::PreRouting, DSTNAT_PRIORITY));
        mgr.remove_mapping(vip(4)).unwrap();
        assert!(!mgr.retry_pending().unwrap());
        mgr.cleanup().unwrap();
    }

    #[test]
    fn rebuild_deletes_and_recreates_the_table_inside_one_batch() {
        let batches = manager_with_mappings(3).rebuild_batches();

        assert_eq!(
            batches.len(),
            1,
            "a rebuild that sends the delete in a batch of its own leaves the \
             fips_gateway table absent between the two sends, so the gateway \
             has no NAT at all in that window: {batches:?}"
        );
        assert_eq!(
            batches[0][..3],
            [
                NatOp::Table(MsgType::Add),
                NatOp::Table(MsgType::Del),
                NatOp::Table(MsgType::Add),
            ],
            "the delete needs a preceding add so it always has a target, and a \
             following add to recreate the table inside the same transaction"
        );
    }

    #[test]
    fn rebuild_deletes_the_table_exactly_once_and_before_every_rule() {
        let batches = manager_with_mappings(2).rebuild_batches();
        let ops = &batches[0];

        let deletes: Vec<usize> = ops
            .iter()
            .enumerate()
            .filter(|(_, op)| matches!(op, NatOp::Table(MsgType::Del)))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(deletes, vec![1], "the table is deleted once, at index 1");

        // Everything that lives in the table has to be added after the delete
        // and the recreate, or the delete would take it back out again.
        for (index, op) in ops.iter().enumerate() {
            if matches!(op, NatOp::Table(_)) {
                continue;
            }
            assert!(
                index > 2,
                "{op:?} at index {index} would be removed by the table delete"
            );
        }
    }

    #[test]
    fn rebuild_emits_a_dnat_and_an_snat_for_every_mapping() {
        let ops = manager_with_mappings(3).rebuild_batches().remove(0);

        for i in 1..=3u16 {
            assert!(ops.contains(&NatOp::Dnat(vip(i))), "no DNAT for {}", vip(i));
            assert!(ops.contains(&NatOp::Snat(vip(i))), "no SNAT for {}", vip(i));
        }
        assert!(ops.contains(&NatOp::FipsMasquerade));
        assert!(!ops.contains(&NatOp::LanMasquerade), "no port forwards");
    }

    #[test]
    fn rebuild_emits_the_lan_masquerade_once_when_port_forwards_exist() {
        let mut mgr = manager_with_mappings(1);
        mgr.port_forwards = vec![
            PortForward {
                proto: Proto::Tcp,
                listen_port: 8080,
                target: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0),
            },
            PortForward {
                proto: Proto::Udp,
                listen_port: 5353,
                target: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0),
            },
        ];

        let ops = mgr.rebuild_batches().remove(0);

        assert!(ops.contains(&NatOp::PortForward(0)));
        assert!(ops.contains(&NatOp::PortForward(1)));
        assert_eq!(
            ops.iter()
                .filter(|op| matches!(op, NatOp::LanMasquerade))
                .count(),
            1
        );
    }

    #[test]
    fn rebuild_places_the_lan_masquerade_before_every_mapping_snat() {
        let mut mgr = manager_with_mappings(3);
        mgr.port_forwards = vec![PortForward {
            proto: Proto::Tcp,
            listen_port: 8080,
            target: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0),
        }];

        let ops = mgr.rebuild_batches().remove(0);

        let masquerade = ops
            .iter()
            .position(|op| matches!(op, NatOp::LanMasquerade))
            .expect("a port forward emits the LAN masquerade");
        let snats: Vec<usize> = ops
            .iter()
            .enumerate()
            .filter(|(_, op)| matches!(op, NatOp::Snat(_)))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(snats.len(), 3, "one SNAT per mapping: {ops:?}");
        for snat in snats {
            assert!(
                masquerade < snat,
                "the LAN masquerade at index {masquerade} follows the SNAT at \
                 index {snat}, so an inbound forwarded flow from a peer with a \
                 live mapping takes the SNAT and bypasses the masquerade: \
                 {ops:?}"
            );
        }
    }

    /// Every rule a rebuild of `mgr` adds, in order.
    fn emitted_rules(mgr: &NatManager) -> Vec<Rule> {
        mgr.rebuild_batches()
            .into_iter()
            .flatten()
            .filter_map(|op| mgr.rule_for(op).expect("the rule builds"))
            .collect()
    }

    /// Every chain a rebuild of `mgr` adds, in order.
    fn emitted_chains(mgr: &NatManager) -> Vec<&Chain> {
        mgr.rebuild_batches()
            .into_iter()
            .flatten()
            .filter_map(|op| mgr.chain_for(op))
            .collect()
    }

    /// The expressions of a rule, in order.
    fn expressions(rule: &Rule) -> Vec<ExpressionVariant> {
        rule.get_expressions()
            .map(|list| list.iter().filter_map(|e| e.get_data().cloned()).collect())
            .unwrap_or_default()
    }

    /// Whether `rule` holds `expected` as consecutive expressions.
    fn has_sequence(rule: &Rule, expected: &[ExpressionVariant]) -> bool {
        expressions(rule)
            .windows(expected.len())
            .any(|window| window == expected)
    }

    /// Whether `rule` holds every expression of `expected`, in that order,
    /// though not necessarily adjacent.
    fn has_in_order(rule: &Rule, expected: &[ExpressionVariant]) -> bool {
        let mut wanted = expected.iter().peekable();
        for expr in expressions(rule) {
            if wanted.peek() == Some(&&expr) {
                wanted.next();
            }
        }
        wanted.peek().is_none()
    }

    /// A `meta <key>` load followed by a compare.
    fn meta_cmp(key: MetaType, op: CmpOp, data: &[u8]) -> [ExpressionVariant; 2] {
        [
            ExpressionVariant::from(Meta::new(key)),
            ExpressionVariant::from(Cmp::new(op, data.to_vec())),
        ]
    }

    #[test]
    fn rebuild_adds_the_nat_chains_with_their_hooks() {
        let mgr = manager_with_mappings(1);
        let chains = emitted_chains(&mgr);
        let hook = |name: &str| {
            let chain = chains
                .iter()
                .find(|c| c.get_name().map(String::as_str) == Some(name))
                .unwrap_or_else(|| panic!("no chain named {name}"));
            chain.get_hook().cloned().expect("a base chain has a hook")
        };
        assert_eq!(
            hook(PREROUTING_CHAIN),
            Hook::new(HookClass::PreRouting, DSTNAT_PRIORITY)
        );
        assert_eq!(
            hook(POSTROUTING_CHAIN),
            Hook::new(HookClass::PostRouting, SRCNAT_PRIORITY)
        );
    }

    #[test]
    fn lan_ingress_rules_keep_their_shape() {
        let mut mgr = manager_with_mappings(1);
        mgr.port_forwards = vec![PortForward {
            proto: Proto::Tcp,
            listen_port: 8080,
            target: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0),
        }];
        let rules = emitted_rules(&mgr);
        let from_tun = meta_cmp(MetaType::IifName, CmpOp::Eq, TUN_IFACE);
        let to_lan = meta_cmp(MetaType::OifName, CmpOp::Eq, b"br-lan\0");

        let forward_dnat = rules
            .iter()
            .filter(|rule| {
                has_sequence(rule, &from_tun)
                    && expressions(rule).iter().any(|e| {
                        matches!(e, ExpressionVariant::Nat(nat) if nat.get_port_register().is_some())
                    })
            })
            .count();
        assert_eq!(
            forward_dnat, 1,
            "the port-forward DNAT matches iifname fips0"
        );

        let lan_masquerade: Vec<&Rule> = rules
            .iter()
            .filter(|rule| {
                expressions(rule)
                    .iter()
                    .any(|e| matches!(e, ExpressionVariant::Masquerade(_)))
                    && has_sequence(rule, &to_lan)
            })
            .collect();
        assert_eq!(lan_masquerade.len(), 1);
        assert!(
            has_in_order(
                lan_masquerade[0],
                &[from_tun[0].clone(), from_tun[1].clone(), to_lan[0].clone()]
            ),
            "the LAN masquerade matches iifname fips0 and oifname br-lan"
        );
    }

    /// The `ip6 daddr` load.
    fn daddr() -> ExpressionVariant {
        ExpressionVariant::from(
            HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Daddr)).build(),
        )
    }

    /// A verdict that drops the packet.
    fn drop_verdict() -> ExpressionVariant {
        ExpressionVariant::from(Immediate::new_verdict(rustables::expr::VerdictKind::Drop))
    }

    /// Whether `rule` is a mapping DNAT, matching a virtual IP of
    /// `manager_with_mappings(count)` as its destination.
    fn is_mapping_dnat(rule: &Rule, count: u16) -> bool {
        let dnat = expressions(rule).iter().any(|e| {
            matches!(e, ExpressionVariant::Nat(nat)
                if nat.get_nat_type() == Some(&NatType::DNat) && nat.get_port_register().is_none())
        });
        dnat && (1..=count).any(|i| {
            has_sequence(
                rule,
                &[
                    daddr(),
                    ExpressionVariant::from(Cmp::new(CmpOp::Eq, vip(i).octets())),
                ],
            )
        })
    }

    #[test]
    fn every_mapping_dnat_matches_only_the_lan_interface() {
        let mgr = manager_with_mappings(2);
        let rules = emitted_rules(&mgr);
        let dnats: Vec<&Rule> = rules.iter().filter(|r| is_mapping_dnat(r, 2)).collect();
        assert_eq!(dnats.len(), 2, "one DNAT per mapping must be found first");

        let from_lan = meta_cmp(MetaType::IifName, CmpOp::Eq, b"br-lan\0");
        for rule in dnats {
            assert!(
                has_sequence(rule, &from_lan),
                "a mapping DNAT does not match iifname br-lan, so a host on any \
                 interface of the gateway can use the mapping: {:?}",
                expressions(rule)
            );
        }
    }

    #[test]
    fn the_fips0_masquerade_matches_only_the_lan_interface() {
        let mgr = manager_with_mappings(2);
        let to_tun = meta_cmp(MetaType::OifName, CmpOp::Eq, TUN_IFACE);
        let rules = emitted_rules(&mgr);
        let masquerades: Vec<&Rule> = rules
            .iter()
            .filter(|rule| {
                has_sequence(rule, &to_tun)
                    && expressions(rule)
                        .iter()
                        .any(|e| matches!(e, ExpressionVariant::Masquerade(_)))
            })
            .collect();
        assert_eq!(masquerades.len(), 1, "one fips0 masquerade");
        assert!(
            has_sequence(
                masquerades[0],
                &meta_cmp(MetaType::IifName, CmpOp::Eq, b"br-lan\0")
            ),
            "the fips0 masquerade does not match iifname br-lan, so traffic from \
             any interface leaves on the mesh under the gateway's identity: {:?}",
            expressions(masquerades[0])
        );
    }

    #[test]
    fn new_flows_into_fips0_from_other_interfaces_are_dropped() {
        let mgr = manager_with_mappings(2);
        let mask = (ConnTrackState::ESTABLISHED | ConnTrackState::RELATED)
            .bits()
            .to_ne_bytes();
        let [oif, oif_cmp] = meta_cmp(MetaType::OifName, CmpOp::Eq, TUN_IFACE);
        let [iif, iif_cmp] = meta_cmp(MetaType::IifName, CmpOp::Neq, b"br-lan\0");
        let expected = [
            oif,
            oif_cmp,
            iif,
            iif_cmp,
            ExpressionVariant::from(Conntrack::new(ConntrackKey::State)),
            ExpressionVariant::from(Bitwise::new(mask, [0u8; 4]).expect("equal lengths")),
            ExpressionVariant::from(Cmp::new(CmpOp::Eq, [0u8; 4])),
            drop_verdict(),
        ];
        let rules = emitted_rules(&mgr);
        assert!(
            rules.iter().any(|rule| has_in_order(rule, &expected)),
            "no rule drops traffic into fips0 from another interface unless it is \
             established or related"
        );
    }

    #[test]
    fn traffic_to_the_pool_from_other_interfaces_is_dropped_before_conntrack() {
        let mgr = manager_with_mappings(2);
        let chains = emitted_chains(&mgr);
        let raw = chains
            .iter()
            .find(|c| c.get_name().map(String::as_str) == Some("raw_prerouting"))
            .expect("a raw_prerouting chain is emitted");
        assert_eq!(
            raw.get_hook().cloned(),
            Some(Hook::new(HookClass::PreRouting, -300)),
            "the pool drop must run before conntrack, at raw priority"
        );

        let (network, prefix) = TEST_POOL;
        let mask = (u128::MAX << (128 - u32::from(prefix))).to_be_bytes();
        let [iif, lan_cmp] = meta_cmp(MetaType::IifName, CmpOp::Neq, b"br-lan\0");
        let [_, lo_cmp] = meta_cmp(MetaType::IifName, CmpOp::Neq, b"lo\0");
        let expected = [
            iif.clone(),
            lan_cmp,
            iif,
            lo_cmp,
            daddr(),
            ExpressionVariant::from(Bitwise::new(mask, [0u8; 16]).expect("equal lengths")),
            ExpressionVariant::from(Cmp::new(CmpOp::Eq, network.octets())),
            drop_verdict(),
        ];
        let rules = emitted_rules(&mgr);
        assert!(
            rules.iter().any(|rule| {
                rule.get_chain().map(String::as_str) == Some("raw_prerouting")
                    && has_in_order(rule, &expected)
            }),
            "no raw_prerouting rule drops traffic to the pool from other interfaces"
        );
    }

    #[test]
    fn forged_mesh_sources_are_dropped_unless_they_arrive_on_fips0_or_loopback() {
        let mgr = manager_with_mappings(2);
        let (set, _) = mgr.mesh_sources().unwrap();
        let [iif, tun_cmp] = meta_cmp(MetaType::IifName, CmpOp::Neq, TUN_IFACE);
        let [_, lo_cmp] = meta_cmp(MetaType::IifName, CmpOp::Neq, b"lo\0");
        let expected = [
            iif.clone(),
            tun_cmp,
            iif,
            lo_cmp,
            ExpressionVariant::from(
                HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Saddr)).build(),
            ),
            ExpressionVariant::from(Lookup::new(&set).unwrap()),
            drop_verdict(),
        ];
        let rules = emitted_rules(&mgr);
        let drops: Vec<&Rule> = rules
            .iter()
            .filter(|rule| {
                rule.get_chain().map(String::as_str) == Some("raw_prerouting")
                    && has_in_order(rule, &expected)
            })
            .collect();
        assert_eq!(
            drops.len(),
            1,
            "no raw_prerouting rule drops a mapped mesh source arriving on another interface"
        );
        let lookup = expressions(drops[0]).into_iter().find_map(|e| match e {
            ExpressionVariant::Lookup(lookup) => Some(lookup),
            _ => None,
        });
        let lookup = lookup.expect("the drop looks the source up");
        assert_eq!(
            lookup.get_set().map(String::as_str),
            Some("fips_mesh_sources")
        );
        assert_eq!(lookup.get_set_id(), Some(&MESH_SOURCE_SET_ID));
    }

    /// The mesh addresses in an element list, in order.
    fn elements(list: &SetElementList) -> Vec<Ipv6Addr> {
        list.get_elements()
            .map(|elements| {
                elements
                    .iter()
                    .filter_map(|e| e.get_key().and_then(|k| k.get_value()))
                    .map(|bytes| {
                        let octets: [u8; 16] = bytes.as_slice().try_into().expect("16 bytes");
                        Ipv6Addr::from(octets)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn the_mesh_source_set_holds_every_mapped_mesh_address() {
        let mut mgr = manager_with_mappings(3);
        let (set, list) = mgr.mesh_sources().unwrap();
        assert_eq!(
            set.family,
            ProtocolFamily::Inet,
            "a set left at the unspecified family is rejected with the table not found"
        );
        assert_eq!(set.get_id(), Some(&MESH_SOURCE_SET_ID));
        assert_eq!(elements(&list), vec![mesh(1), mesh(2), mesh(3)]);

        // A reissued address can be mapped to the same node as another
        // while a removal is queued; the node's address is listed once.
        mgr.mappings.insert(
            vip(9),
            NatMapping {
                virtual_ip: vip(9),
                mesh_addr: mesh(2),
            },
        );
        let (_, list) = mgr.mesh_sources().unwrap();
        assert_eq!(elements(&list), vec![mesh(1), mesh(2), mesh(3)]);
    }

    #[test]
    fn no_element_list_is_sent_without_mappings() {
        let ops = manager_with_mappings(0).rebuild_batches().remove(0);
        assert!(ops.contains(&NatOp::MeshSourceSet));
        assert!(!ops.contains(&NatOp::MeshSourceElements));
        let ops = manager_with_mappings(1).rebuild_batches().remove(0);
        let set = ops.iter().position(|op| *op == NatOp::MeshSourceSet);
        let elements = ops.iter().position(|op| *op == NatOp::MeshSourceElements);
        let lookup = ops.iter().position(|op| *op == NatOp::ForgedSourceDrop);
        assert!(set < elements && elements < lookup, "{ops:?}");
        manager_with_mappings(0)
            .encode_batch(&manager_with_mappings(0).rebuild_batches().remove(0))
            .expect("a rebuild with no mappings encodes");
    }

    #[test]
    fn a_removal_is_reported_only_once_the_rebuild_succeeded() {
        let mut mgr = manager_with_mappings(2);
        // Make encoding, and so the rebuild, fail.
        mgr.pre_chain = Chain::new(&mgr.table);
        let applied = mgr.apply(&[NatCommand::Remove {
            virtual_ip: vip(1),
            mesh_addr: mesh(1),
        }]);
        assert!(
            applied.outcomes[0].1.is_err(),
            "control: the rebuild failed"
        );
        assert!(
            applied.removed.is_empty(),
            "a removal was reported while the kernel may still hold its rules"
        );

        mgr.track_rebuild(|_| Ok(())).unwrap();
        assert_eq!(mgr.removed, vec![(vip(1), mesh(1))]);
    }

    /// A NAT table that records the commands it is given, taking `delay` per
    /// apply, as a slow netlink rebuild would.
    struct SlowTable {
        delay: Duration,
        recorded: Arc<std::sync::Mutex<Vec<NatCommand>>>,
        mappings: HashMap<Ipv6Addr, Ipv6Addr>,
    }

    impl SlowTable {
        fn new(delay: Duration) -> Self {
            Self {
                delay,
                recorded: Arc::default(),
                mappings: HashMap::new(),
            }
        }
    }

    impl NatTable for SlowTable {
        fn apply(&mut self, commands: &[NatCommand]) -> NatApplied {
            std::thread::sleep(self.delay);
            self.recorded.lock().unwrap().extend_from_slice(commands);
            for command in commands {
                match *command {
                    NatCommand::Add {
                        virtual_ip,
                        mesh_addr,
                    } => {
                        self.mappings.insert(virtual_ip, mesh_addr);
                    }
                    NatCommand::Remove { virtual_ip, .. } => {
                        self.mappings.remove(&virtual_ip);
                    }
                }
            }
            NatApplied {
                outcomes: commands.iter().map(|c| (*c, Ok(()))).collect(),
                removed: Vec::new(),
            }
        }

        fn retry_pending(&mut self) -> (Result<bool, NatError>, Vec<(Ipv6Addr, Ipv6Addr)>) {
            (Ok(false), Vec::new())
        }

        fn mapping_count(&self) -> usize {
            self.mappings.len()
        }

        fn cleanup(self: Box<Self>) -> Result<(), NatError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn nat_changes_do_not_stall_the_runtime_thread() {
        let table = SlowTable::new(Duration::from_millis(200));
        let recorded = Arc::clone(&table.recorded);
        let (mut driver, _reports) = NatDriver::start(Box::new(table));

        let origin = Instant::now();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let timer = tokio::spawn(async move {
            let _ = started_tx.send(());
            tokio::time::sleep(Duration::from_millis(10)).await;
            origin.elapsed()
        });
        started_rx.await.expect("the timer task started");

        for i in 1..=10u16 {
            driver
                .submit(NatCommand::Add {
                    virtual_ip: vip(i),
                    mesh_addr: mesh(i),
                })
                .expect("the driver takes the command");
        }
        let observed = timer.await.expect("the timer task ran");
        assert!(
            observed <= Duration::from_millis(500),
            "a 10 ms timer on the runtime thread fired after {observed:?}: \
             submitting NAT changes blocked the thread that answers .fips queries"
        );

        // Control: the commands were applied, not dropped.
        let deadline = Instant::now() + Duration::from_secs(5);
        while driver.mapping_count() < 10 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(driver.mapping_count(), 10);
        assert_eq!(recorded.lock().unwrap().len(), 10);
    }

    /// A NAT table whose behaviour each test sets, recording what it is
    /// asked to do.
    #[derive(Default)]
    struct FakeTable {
        /// Every batch `apply` was given, in order.
        batches: Arc<std::sync::Mutex<Vec<Vec<NatCommand>>>>,
        mappings: HashMap<Ipv6Addr, Ipv6Addr>,
        /// When set, the first `apply` signals entry and then waits for the
        /// release.
        gate: Option<(
            crossbeam_channel::Sender<()>,
            crossbeam_channel::Receiver<()>,
        )>,
        /// Panic in `apply`.
        panics: bool,
        /// Fail every `apply` with this error.
        fails: Option<NatError>,
        /// How long `cleanup` takes.
        cleanup_delay: Duration,
        /// Set when `cleanup` runs.
        cleaned: Arc<std::sync::atomic::AtomicBool>,
        /// Set when the table is dropped.
        dropped: DropFlag,
    }

    /// A flag set when its holder is dropped.
    #[derive(Default)]
    struct DropFlag(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    impl NatTable for FakeTable {
        fn apply(&mut self, commands: &[NatCommand]) -> NatApplied {
            assert!(!self.panics, "the fake table panics on apply");
            if let Some((entered, release)) = self.gate.take() {
                let _ = entered.send(());
                let _ = release.recv();
            }
            self.batches.lock().unwrap().push(commands.to_vec());
            for command in commands {
                match *command {
                    NatCommand::Add {
                        virtual_ip,
                        mesh_addr,
                    } => {
                        self.mappings.insert(virtual_ip, mesh_addr);
                    }
                    NatCommand::Remove { virtual_ip, .. } => {
                        self.mappings.remove(&virtual_ip);
                    }
                }
            }
            NatApplied {
                outcomes: commands
                    .iter()
                    .map(|c| (*c, self.fails.clone().map_or(Ok(()), Err)))
                    .collect(),
                removed: Vec::new(),
            }
        }

        fn retry_pending(&mut self) -> (Result<bool, NatError>, Vec<(Ipv6Addr, Ipv6Addr)>) {
            (Ok(false), Vec::new())
        }

        fn mapping_count(&self) -> usize {
            self.mappings.len()
        }

        fn cleanup(self: Box<Self>) -> Result<(), NatError> {
            std::thread::sleep(self.cleanup_delay);
            self.cleaned.store(true, Ordering::SeqCst);
            Err(NatError::Nftables("cleanup ran".into()))
        }
    }

    /// Poll `done` until it holds or five seconds pass.
    fn eventually(mut done: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if done() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        done()
    }

    #[test]
    fn nat_worker_applies_add_remove_and_readd_in_order() {
        let table = FakeTable::default();
        let batches = Arc::clone(&table.batches);
        let (mut driver, _reports) = NatDriver::start(Box::new(table));
        let commands = [
            NatCommand::Add {
                virtual_ip: vip(1),
                mesh_addr: mesh(1),
            },
            NatCommand::Remove {
                virtual_ip: vip(1),
                mesh_addr: mesh(1),
            },
            NatCommand::Add {
                virtual_ip: vip(1),
                mesh_addr: mesh(2),
            },
        ];
        for command in commands {
            driver.submit(command).unwrap();
        }
        assert!(eventually(|| batches.lock().unwrap().concat().len() == 3));
        assert_eq!(batches.lock().unwrap().concat(), commands);
        assert_eq!(driver.mapping_count(), 1);
    }

    #[test]
    fn a_stale_remove_does_not_unmap_a_reissued_address() {
        let mut mgr = manager_with_mappings(0);
        // Make encoding, and so every rebuild, fail without a socket.
        mgr.pre_chain = Chain::new(&mgr.table);
        mgr.apply(&[NatCommand::Add {
            virtual_ip: vip(1),
            mesh_addr: mesh(2),
        }]);
        let applied = mgr.apply(&[NatCommand::Remove {
            virtual_ip: vip(1),
            mesh_addr: mesh(1),
        }]);
        assert!(matches!(
            applied.outcomes[0].1,
            Err(NatError::RuleNotFound(_))
        ));
        assert_eq!(
            mgr.mappings.get(&vip(1)).map(|m| m.mesh_addr),
            Some(mesh(2)),
            "a removal for the address's previous holder unmapped its new one"
        );
        assert!(
            applied.removed.is_empty(),
            "the old pair is reported only after a rebuild without it succeeds"
        );
        mgr.track_rebuild(|_| Ok(())).unwrap();
        assert_eq!(mgr.removed, vec![(vip(1), mesh(1))]);
    }

    #[test]
    fn queued_changes_are_applied_in_one_rebuild() {
        let (entered_tx, entered_rx) = crossbeam_channel::bounded(1);
        let (release_tx, release_rx) = crossbeam_channel::bounded(1);
        let table = FakeTable {
            gate: Some((entered_tx, release_rx)),
            ..FakeTable::default()
        };
        let batches = Arc::clone(&table.batches);
        let (mut driver, _reports) = NatDriver::start(Box::new(table));
        let add = |i| NatCommand::Add {
            virtual_ip: vip(i),
            mesh_addr: mesh(i),
        };
        driver.submit(add(1)).unwrap();
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the first apply started");
        for i in 2..=10 {
            driver.submit(add(i)).unwrap();
        }
        release_tx.send(()).unwrap();
        assert!(eventually(|| batches.lock().unwrap().len() == 2));
        let batches = batches.lock().unwrap();
        assert_eq!(batches.len(), 2, "{batches:?}");
        assert_eq!(batches[1].len(), 9, "the queued changes share one rebuild");
    }

    #[test]
    fn stop_runs_cleanup_and_reports_it() {
        let table = FakeTable::default();
        let cleaned = Arc::clone(&table.cleaned);
        let (driver, _reports) = NatDriver::start(Box::new(table));
        let result = driver.shutdown(Duration::from_secs(5));
        assert!(cleaned.load(Ordering::SeqCst), "cleanup ran");
        assert!(
            matches!(result, Err(NatError::Nftables(ref m)) if m == "cleanup ran"),
            "the cleanup's result is reported: {result:?}"
        );
    }

    #[test]
    fn a_stop_queued_behind_changes_still_runs_cleanup() {
        let (entered_tx, entered_rx) = crossbeam_channel::bounded(1);
        let (release_tx, release_rx) = crossbeam_channel::bounded(1);
        let table = FakeTable {
            gate: Some((entered_tx, release_rx)),
            ..FakeTable::default()
        };
        let cleaned = Arc::clone(&table.cleaned);
        let (mut driver, _reports) = NatDriver::start(Box::new(table));
        let queue = driver.commands.clone();
        driver
            .submit(NatCommand::Add {
                virtual_ip: vip(1),
                mesh_addr: mesh(1),
            })
            .unwrap();
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the first apply started");
        driver
            .submit(NatCommand::Add {
                virtual_ip: vip(2),
                mesh_addr: mesh(2),
            })
            .unwrap();

        // The stop waits in the queue behind the second change, so the
        // worker meets it while draining a batch.
        let started = Instant::now();
        let stopping = std::thread::spawn(move || driver.shutdown(NAT_STOP_TIMEOUT));
        assert!(
            eventually(|| queue.len() == 2),
            "control: the change and the stop are queued"
        );
        release_tx.send(()).unwrap();
        let result = stopping.join().unwrap();
        assert!(
            started.elapsed() < NAT_STOP_TIMEOUT / 2,
            "the stop was lost in the batch; shutdown waited {:?}",
            started.elapsed()
        );
        assert!(cleaned.load(Ordering::SeqCst), "cleanup ran");
        assert!(
            matches!(result, Err(NatError::Nftables(ref m)) if m == "cleanup ran"),
            "the cleanup's result is reported: {result:?}"
        );
    }

    #[test]
    fn stop_returns_after_the_timeout_when_the_worker_hangs() {
        let table = FakeTable {
            cleanup_delay: Duration::from_secs(3),
            ..FakeTable::default()
        };
        let (driver, _reports) = NatDriver::start(Box::new(table));
        let started = Instant::now();
        let _ = driver.shutdown(Duration::from_millis(100));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown waited {:?} for a hung cleanup",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_worker_panic_is_reported_to_the_driver() {
        let table = FakeTable {
            panics: true,
            ..FakeTable::default()
        };
        let (mut driver, reports) = NatDriver::start(Box::new(table));
        driver
            .submit(NatCommand::Add {
                virtual_ip: vip(1),
                mesh_addr: mesh(1),
            })
            .unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(5), reports.exit).await;
        assert!(ended.is_ok(), "the worker's end was not reported");
        assert!(
            eventually(|| driver
                .submit(NatCommand::Remove {
                    virtual_ip: vip(1),
                    mesh_addr: mesh(1),
                })
                .is_err()),
            "submitting to a stopped worker must fail"
        );
    }

    #[test]
    fn a_dropped_driver_ends_its_worker() {
        let table = FakeTable::default();
        let dropped = Arc::clone(&table.dropped.0);
        let cleaned = Arc::clone(&table.cleaned);
        let (driver, _reports) = NatDriver::start(Box::new(table));
        drop(driver);
        assert!(
            eventually(|| dropped.load(Ordering::SeqCst)),
            "the worker did not end"
        );
        assert!(
            !cleaned.load(Ordering::SeqCst),
            "no cleanup without shutdown"
        );
    }

    #[test]
    fn apply_failures_log_once_per_change_of_outcome() {
        let mut table = FakeTable {
            fails: Some(NatError::Kernel {
                errno: Errno(libc::ENOBUFS),
                seq: 3,
            }),
            ..FakeTable::default()
        };
        let mut log = RetryLog::default();
        let mut reports = Vec::new();
        for i in 1..=10u16 {
            let batch = [NatCommand::Add {
                virtual_ip: vip(i),
                mesh_addr: mesh(i),
            }];
            let applied = table.apply(&batch);
            reports.push(report_apply(&mut log, &batch, &applied));
        }
        assert_eq!(reports[0], RetryReport::Failed);
        assert!(
            reports[1..].iter().all(|r| *r == RetryReport::Repeated),
            "a persistent failure logged more than once: {reports:?}"
        );

        table.fails = None;
        let batch = [NatCommand::Remove {
            virtual_ip: vip(1),
            mesh_addr: mesh(1),
        }];
        let applied = table.apply(&batch);
        assert_eq!(
            report_apply(&mut log, &batch, &applied),
            RetryReport::Recovered
        );
        // A stale remove is not a failure.
        let stale = NatApplied {
            outcomes: vec![(batch[0], Err(NatError::RuleNotFound(vip(1))))],
            removed: Vec::new(),
        };
        assert_eq!(report_apply(&mut log, &batch, &stale), RetryReport::Clean);
    }

    #[test]
    fn a_batch_of_stale_removes_during_a_failure_does_not_report_recovery() {
        let failure = NatError::Kernel {
            errno: Errno(libc::ENOBUFS),
            seq: 3,
        };
        let mut log = RetryLog::default();
        let add = [NatCommand::Add {
            virtual_ip: vip(1),
            mesh_addr: mesh(1),
        }];
        let failed = NatApplied {
            outcomes: vec![(add[0], Err(failure.clone()))],
            removed: Vec::new(),
        };
        assert_eq!(report_apply(&mut log, &add, &failed), RetryReport::Failed);

        // Nothing reached the kernel: the remove named a mapping already gone.
        let remove = [NatCommand::Remove {
            virtual_ip: vip(2),
            mesh_addr: mesh(2),
        }];
        let stale = NatApplied {
            outcomes: vec![(remove[0], Err(NatError::RuleNotFound(vip(2))))],
            removed: Vec::new(),
        };
        let report = report_apply(&mut log, &remove, &stale);
        assert_ne!(
            report,
            RetryReport::Recovered,
            "a batch that rebuilt nothing reported the failing table as recovered"
        );
        assert_eq!(
            report_apply(&mut log, &add, &failed),
            RetryReport::Repeated,
            "the same failure after a stale remove logged as a new one"
        );
    }

    /// The encoded rebuild of a manager holding `count` mappings.
    fn encoded_rebuild(count: u16) -> Vec<u8> {
        let mgr = manager_with_mappings(count);
        let ops = mgr.rebuild_batches().remove(0);
        mgr.encode_batch(&ops).expect("the rebuild encodes")
    }

    /// One netlink message, padded to 4 bytes.
    fn nlmsg(kind: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let len = (NLMSG_HDRLEN + payload.len()) as u32;
        let mut msg = Vec::new();
        msg.extend_from_slice(&len.to_ne_bytes());
        msg.extend_from_slice(&kind.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(payload);
        msg.resize(msg.len().div_ceil(4) * 4, 0);
        msg
    }

    /// The kernel's `NLMSG_ERROR` reply to message `seq`, as it sends it on a
    /// socket with `NETLINK_CAP_ACK`: the error, then the request's header.
    fn ack(seq: u32, error: i32) -> Vec<u8> {
        let mut payload = error.to_ne_bytes().to_vec();
        payload.extend_from_slice(&nlmsg(0x0a00, seq, &[])[..NLMSG_HDRLEN]);
        nlmsg(libc::NLMSG_ERROR as u16, seq, &payload)
    }

    /// The largest batch the kernel admits: twice its send-buffer clamp,
    /// less the 32 bytes netlink reserves.
    const KERNEL_BATCH_LIMIT: usize = 2_147_483_614;

    #[test]
    fn rebuild_for_2000_mappings_requests_exactly_one_ack_on_the_last_message() {
        let encoded = encoded_rebuild(2000);
        assert!(
            encoded.len() > 212_960,
            "the 2000-mapping batch ({} bytes) must be past the default \
             netlink send limit for this test to cover the large case",
            encoded.len()
        );

        let headers = nl_headers(&encoded).expect("the batch parses");
        assert_eq!(
            headers.first().map(|h| h.kind),
            Some(libc::NFNL_MSG_BATCH_BEGIN as u16)
        );
        assert_eq!(
            headers.last().map(|h| h.kind),
            Some(libc::NFNL_MSG_BATCH_END as u16)
        );
        let acked: Vec<usize> = headers
            .iter()
            .enumerate()
            .filter(|(_, h)| h.flags & libc::NLM_F_ACK as u16 != 0)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            acked,
            vec![headers.len() - 2],
            "only the last object before the batch end may request an ack; \
             one ack per message overflows the receive buffer after the \
             kernel has committed the batch"
        );
    }

    #[test]
    fn sndbuf_for_admits_the_2000_mapping_batch_and_small_batches_after_kernel_doubling() {
        let large = encoded_rebuild(2000).len();
        for len in [large, 0, 1, 212_961] {
            let sndbuf = sndbuf_for(len);
            assert!(
                2 * sndbuf as u64 - 32 >= len as u64,
                "a send buffer of {sndbuf}, doubled by the kernel, refuses a \
                 {len}-byte batch"
            );
        }
    }

    #[test]
    fn sndbuf_for_saturates_at_the_kernel_clamp_for_huge_batches() {
        for len in [2 * MAX_SNDBUF as usize, usize::MAX] {
            assert_eq!(sndbuf_for(len), i32::MAX / 2, "sndbuf_for({len})");
        }
    }

    #[test]
    fn check_admissible_refuses_a_batch_larger_than_the_kernel_can_accept() {
        assert!(check_admissible(KERNEL_BATCH_LIMIT).is_ok());
        for len in [KERNEL_BATCH_LIMIT + 1, usize::MAX] {
            match check_admissible(len) {
                Err(e @ NatError::BatchTooLarge { bytes }) => {
                    assert_eq!(bytes, len);
                    assert!(
                        e.to_string().contains(&len.to_string()),
                        "the error names the batch size: {e}"
                    );
                }
                other => panic!("a {len}-byte batch was admitted: {other:?}"),
            }
        }
    }

    #[test]
    fn ack_reader_fails_on_an_error_that_precedes_the_last_ack() {
        // The kernel aborts the batch on a failing rule mid-batch, reports
        // that rule's error, and still acknowledges the last message.
        let reader = AckReader { last_seq: 4000 };
        let error = ack(1234, -libc::ENOENT);
        let last = ack(4000, 0);

        let expect_error = |result: Result<AckState, NatError>| match result {
            Err(NatError::Kernel { errno, seq }) => {
                assert_eq!(errno, Errno(libc::ENOENT));
                assert_eq!(seq, 1234);
            }
            other => panic!("the aborted batch was not reported: {other:?}"),
        };

        expect_error(reader.feed(&error));
        expect_error(reader.feed(&[error.clone(), last.clone()].concat()));
    }

    #[test]
    fn ack_reader_is_done_only_on_the_last_sequence_ack() {
        let reader = AckReader { last_seq: 10 };

        assert_eq!(reader.feed(&ack(10, 0)).expect("parses"), AckState::Done);
        assert_eq!(reader.feed(&ack(5, 0)).expect("parses"), AckState::Pending);
        assert_eq!(
            reader
                .feed(&nlmsg(libc::NLMSG_NOOP as u16, 10, &[]))
                .expect("parses"),
            AckState::Pending
        );
        assert_eq!(
            reader
                .feed(&[ack(5, 0), ack(10, 0)].concat())
                .expect("parses"),
            AckState::Done
        );

        let whole = ack(10, 0);
        assert!(
            reader.feed(&whole[..8]).is_err(),
            "a header shorter than 16 bytes"
        );
        let mut overlong = whole.clone();
        overlong[..4].copy_from_slice(&((whole.len() + 4) as u32).to_ne_bytes());
        assert!(
            reader.feed(&overlong).is_err(),
            "a length past the end of the datagram"
        );
        let short = nlmsg(libc::NLMSG_ERROR as u16, 10, &[0, 0]);
        assert!(
            reader.feed(&short[..NLMSG_HDRLEN + 2]).is_err(),
            "an NLMSG_ERROR payload shorter than its error field"
        );
    }

    #[test]
    fn kernel_error_display_names_the_errno() {
        let text = NatError::Kernel {
            errno: Errno(libc::EMSGSIZE),
            seq: 7,
        }
        .to_string();
        assert!(text.contains("EMSGSIZE"), "{text}");
        assert!(text.contains(&format!("({})", libc::EMSGSIZE)), "{text}");
    }
}
