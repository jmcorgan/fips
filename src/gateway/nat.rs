//! NAT rule management.
//!
//! Manages nftables DNAT/SNAT rules via the rustables netlink API
//! for translating between virtual IPs and FIPS mesh addresses.

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Instant;
use tracing::{debug, info};

use rustables::expr::{
    Cmp, CmpOp, HighLevelPayload, IPv6HeaderField, Immediate, Masquerade, Meta, MetaType, Nat,
    NatType, NetworkHeaderField, Register, TCPHeaderField, TransportHeaderField, UDPHeaderField,
};
use rustables::{Batch, Chain, ChainType, Hook, HookClass, MsgType, ProtocolFamily, Rule, Table};

use crate::config::{PortForward, Proto};

const TABLE_NAME: &str = "fips_gateway";
const PREROUTING_CHAIN: &str = "prerouting";
const POSTROUTING_CHAIN: &str = "postrouting";

/// NAT priority constants (matching nftables standard priorities).
const DSTNAT_PRIORITY: i32 = -100;
const SRCNAT_PRIORITY: i32 = 100;

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
/// runs inside the gateway's event loop, so this bounds the stall there.
const ACK_TIMEOUT_SECS: libc::time_t = 5;

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
#[derive(Debug, thiserror::Error)]
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
    /// Masquerade for traffic leaving through `fips0`.
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
/// doesn't expose). The table is small (one masquerade + two rules
/// per mapping) so this is cheap.
pub struct NatManager {
    table: Table,
    pre_chain: Chain,
    post_chain: Chain,
    /// LAN interface name, used to gate the port-forward LAN-side
    /// masquerade rule (distinct from the fips0 egress masquerade).
    lan_interface: String,
    /// Active mappings keyed by virtual IP.
    mappings: HashMap<Ipv6Addr, NatMapping>,
    /// Inbound port-forward rules.
    port_forwards: Vec<PortForward>,
    /// Desired state has not yet been acknowledged by the kernel.
    rebuild_pending: bool,
}

impl NatManager {
    /// Build the manager's state without touching netlink.
    ///
    /// Everything `new` does except sending the first rebuild, so a test can
    /// exercise the batch builder with no socket and no privileges.
    fn with_state(lan_interface: String) -> Self {
        let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME);
        let pre_chain = Chain::new(&table)
            .with_name(PREROUTING_CHAIN)
            .with_type(ChainType::Nat)
            .with_hook(Hook::new(HookClass::PreRouting, DSTNAT_PRIORITY));
        let post_chain = Chain::new(&table)
            .with_name(POSTROUTING_CHAIN)
            .with_type(ChainType::Nat)
            .with_hook(Hook::new(HookClass::PostRouting, SRCNAT_PRIORITY));

        Self {
            table,
            pre_chain,
            post_chain,
            lan_interface,
            mappings: HashMap::new(),
            port_forwards: Vec::new(),
            rebuild_pending: false,
        }
    }

    /// Create the nftables table and NAT chains.
    ///
    /// Installs a masquerade rule for traffic exiting via `fips0` so that
    /// LAN client source addresses are rewritten to the gateway's mesh
    /// address, allowing return traffic to route back through the mesh.
    ///
    /// `lan_interface` is the gateway's LAN-facing interface name,
    /// needed by the port-forward LAN-side masquerade rule.
    pub fn new(lan_interface: String) -> Result<Self, NatError> {
        let mgr = Self::with_state(lan_interface);
        mgr.rebuild()?;

        info!("Created nftables table '{TABLE_NAME}' with NAT chains and fips0 masquerade");
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
    pub fn add_mapping(
        &mut self,
        virtual_ip: Ipv6Addr,
        mesh_addr: Ipv6Addr,
    ) -> Result<(), NatError> {
        self.mappings.insert(
            virtual_ip,
            NatMapping {
                virtual_ip,
                mesh_addr,
            },
        );
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

    /// Remove DNAT and SNAT rules for a virtual IP mapping.
    pub fn remove_mapping(&mut self, virtual_ip: Ipv6Addr) -> Result<(), NatError> {
        if self.mappings.remove(&virtual_ip).is_none() {
            return Err(NatError::RuleNotFound(virtual_ip));
        }
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
            NatOp::FipsMasquerade,
        ];

        for mapping in self.mappings.values() {
            ops.push(NatOp::Dnat(mapping.virtual_ip));
            ops.push(NatOp::Snat(mapping.virtual_ip));
        }

        // Inbound port-forward rules. Each forward is one DNAT rule in
        // prerouting keyed on (iif fips0, nfproto ipv6, l4proto, th dport).
        // When any forwards are configured, emit a single LAN-side masquerade
        // in postrouting so the LAN target host sees the gateway's LAN address
        // as source and replies flow back through conntrack.
        for index in 0..self.port_forwards.len() {
            ops.push(NatOp::PortForward(index));
        }
        if !self.port_forwards.is_empty() {
            ops.push(NatOp::LanMasquerade);
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
                NatOp::PreChain => batch.add(&self.pre_chain, MsgType::Add),
                NatOp::PostChain => batch.add(&self.post_chain, MsgType::Add),
                NatOp::FipsMasquerade => {
                    // Rewrite the source address of traffic leaving fips0.
                    // Without this, LAN clients' source addresses (e.g.
                    // fd02::20) are not routable on the mesh, so return
                    // traffic would be black-holed.
                    let rule = Rule::new(&self.post_chain)?
                        .with_expr(Meta::new(MetaType::OifName))
                        .with_expr(Cmp::new(CmpOp::Eq, b"fips0\0".to_vec()))
                        .with_expr(Masquerade::default());
                    batch.add(&rule, MsgType::Add);
                }
                NatOp::Dnat(virtual_ip) => {
                    let mapping = self.mapping(virtual_ip)?;
                    let rule = Rule::new(&self.pre_chain)?
                        .with_expr(Meta::new(MetaType::NfProto))
                        .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                        .with_expr(
                            HighLevelPayload::Network(NetworkHeaderField::IPv6(
                                IPv6HeaderField::Daddr,
                            ))
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
                    batch.add(&rule, MsgType::Add);
                }
                NatOp::Snat(virtual_ip) => {
                    let mapping = self.mapping(virtual_ip)?;
                    let rule = Rule::new(&self.post_chain)?
                        .with_expr(Meta::new(MetaType::NfProto))
                        .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                        .with_expr(
                            HighLevelPayload::Network(NetworkHeaderField::IPv6(
                                IPv6HeaderField::Saddr,
                            ))
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
                    batch.add(&rule, MsgType::Add);
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
                        .with_expr(Cmp::new(CmpOp::Eq, b"fips0\0".to_vec()))
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
                    batch.add(&rule, MsgType::Add);
                }
                NatOp::LanMasquerade => {
                    let mut lan_iface = self.lan_interface.clone().into_bytes();
                    lan_iface.push(0);
                    let rule = Rule::new(&self.post_chain)?
                        .with_expr(Meta::new(MetaType::IifName))
                        .with_expr(Cmp::new(CmpOp::Eq, b"fips0\0".to_vec()))
                        .with_expr(Meta::new(MetaType::OifName))
                        .with_expr(Cmp::new(CmpOp::Eq, lan_iface))
                        .with_expr(Meta::new(MetaType::NfProto))
                        .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                        .with_expr(Masquerade::default());
                    batch.add(&rule, MsgType::Add);
                }
            }
        }
        let mut bytes = batch.finalize();
        keep_last_ack(&mut bytes)?;
        Ok(bytes)
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

    fn rebuild_desired(&mut self) -> Result<(), NatError> {
        self.rebuild_pending = true;
        self.rebuild()?;
        self.rebuild_pending = false;
        Ok(())
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
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV6;

    fn vip(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, last)
    }

    fn mesh(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfd02, 0, 0, 0, 0, 0, 0, last)
    }

    /// A manager holding `count` mappings and no netlink socket.
    fn manager_with_mappings(count: u16) -> NatManager {
        let mut mgr = NatManager::with_state("br-lan".to_string());
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
        let mut mgr = manager_with_mappings(2);
        let table_name = format!("{TABLE_NAME}_retry_test_{}", std::process::id());
        mgr.table = Table::new(ProtocolFamily::Inet).with_name(&table_name);
        mgr.pre_chain = Chain::new(&mgr.table)
            .with_name(PREROUTING_CHAIN)
            .with_type(ChainType::Nat)
            .with_hook(Hook::new(HookClass::PreRouting, DSTNAT_PRIORITY));
        mgr.post_chain = Chain::new(&mgr.table)
            .with_name(POSTROUTING_CHAIN)
            .with_type(ChainType::Nat)
            .with_hook(Hook::new(HookClass::PostRouting, SRCNAT_PRIORITY));
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
            3
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
