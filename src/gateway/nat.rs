//! NAT rule management.
//!
//! Manages nftables DNAT/SNAT rules via the rustables netlink API
//! for translating between virtual IPs and FIPS mesh addresses.

use std::collections::HashMap;
use std::net::Ipv6Addr;
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

/// Errors from NAT operations.
#[derive(Debug, thiserror::Error)]
pub enum NatError {
    #[error("nftables error: {0}")]
    Nftables(String),
    #[error("rule not found for virtual IP {0}")]
    RuleNotFound(Ipv6Addr),
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
    /// Inbound port-forward rules (TASK-2026-0061).
    port_forwards: Vec<PortForward>,
}

impl NatManager {
    /// Create the nftables table and NAT chains.
    ///
    /// Installs a masquerade rule for traffic exiting via `fips0` so that
    /// LAN client source addresses are rewritten to the gateway's mesh
    /// address, allowing return traffic to route back through the mesh.
    ///
    /// `lan_interface` is the gateway's LAN-facing interface name,
    /// needed by the port-forward LAN-side masquerade rule.
    pub fn new(lan_interface: String) -> Result<Self, NatError> {
        let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME);
        let pre_chain = Chain::new(&table)
            .with_name(PREROUTING_CHAIN)
            .with_type(ChainType::Nat)
            .with_hook(Hook::new(HookClass::PreRouting, DSTNAT_PRIORITY));
        let post_chain = Chain::new(&table)
            .with_name(POSTROUTING_CHAIN)
            .with_type(ChainType::Nat)
            .with_hook(Hook::new(HookClass::PostRouting, SRCNAT_PRIORITY));

        let mgr = Self {
            table,
            pre_chain,
            post_chain,
            lan_interface,
            mappings: HashMap::new(),
            port_forwards: Vec::new(),
        };
        mgr.rebuild()?;

        info!("Created nftables table '{TABLE_NAME}' with NAT chains and fips0 masquerade");
        Ok(mgr)
    }

    /// Replace the current inbound port-forward rule set and rebuild
    /// the nftables table atomically. Pass an empty slice to clear.
    pub fn set_port_forwards(&mut self, forwards: &[PortForward]) -> Result<(), NatError> {
        self.port_forwards = forwards.to_vec();
        self.rebuild()?;
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
        self.rebuild()?;

        debug!(
            virtual_ip = %virtual_ip,
            mesh_addr = %mesh_addr,
            "Added DNAT/SNAT rules"
        );
        Ok(())
    }

    /// Remove DNAT and SNAT rules for a virtual IP mapping.
    pub fn remove_mapping(&mut self, virtual_ip: Ipv6Addr) -> Result<(), NatError> {
        if self.mappings.remove(&virtual_ip).is_none() {
            return Err(NatError::RuleNotFound(virtual_ip));
        }
        self.rebuild()?;

        debug!(virtual_ip = %virtual_ip, "Removed DNAT/SNAT rules");
        Ok(())
    }

    /// Flush all rules and delete the nftables table.
    pub fn cleanup(self) -> Result<(), NatError> {
        let mut batch = Batch::new();
        batch.add(&self.table, MsgType::Del);
        batch
            .send()
            .map_err(|e| NatError::Nftables(e.to_string()))?;

        info!("Deleted nftables table '{TABLE_NAME}'");
        Ok(())
    }

    /// Number of active NAT mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// Atomically rebuild the entire nftables table with all current
    /// rules. Deletes and recreates the table, chains, masquerade rule,
    /// and all per-mapping DNAT/SNAT rules in a single netlink batch.
    fn rebuild(&self) -> Result<(), NatError> {
        // Delete existing table in a separate batch — ignore ENOENT on
        // first call when the table doesn't exist yet.
        let mut del_batch = Batch::new();
        del_batch.add(&self.table, MsgType::Del);
        let _ = del_batch.send();

        // Recreate table, chains, and all rules atomically.
        let mut batch = Batch::new();
        batch.add(&self.table, MsgType::Add);
        batch.add(&self.pre_chain, MsgType::Add);
        batch.add(&self.post_chain, MsgType::Add);

        // Masquerade rule: rewrite source address for traffic exiting fips0.
        // Without this, LAN clients' source addresses (e.g. fd02::20) are
        // not routable on the mesh, so return traffic would be black-holed.
        let masq_rule = Rule::new(&self.post_chain)?
            .with_expr(Meta::new(MetaType::OifName))
            .with_expr(Cmp::new(CmpOp::Eq, b"fips0\0".to_vec()))
            .with_expr(Masquerade::default());
        batch.add(&masq_rule, MsgType::Add);

        // Per-mapping DNAT/SNAT rules.
        for mapping in self.mappings.values() {
            let dnat_rule = Rule::new(&self.pre_chain)?
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
            batch.add(&dnat_rule, MsgType::Add);

            let snat_rule = Rule::new(&self.post_chain)?
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
            batch.add(&snat_rule, MsgType::Add);
        }

        // Inbound port-forward rules (TASK-2026-0061). Each forward is
        // one DNAT rule in prerouting keyed on (iif fips0, nfproto ipv6,
        // l4proto, th dport). When any forwards are configured, emit a
        // single LAN-side masquerade in postrouting so the LAN target
        // host sees the gateway's LAN address as source and replies
        // flow back through conntrack.
        for pf in &self.port_forwards {
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

            let dnat_rule = Rule::new(&self.pre_chain)?
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
            batch.add(&dnat_rule, MsgType::Add);
        }

        if !self.port_forwards.is_empty() {
            let mut lan_iface = self.lan_interface.clone().into_bytes();
            lan_iface.push(0);
            let lan_masq = Rule::new(&self.post_chain)?
                .with_expr(Meta::new(MetaType::IifName))
                .with_expr(Cmp::new(CmpOp::Eq, b"fips0\0".to_vec()))
                .with_expr(Meta::new(MetaType::OifName))
                .with_expr(Cmp::new(CmpOp::Eq, lan_iface))
                .with_expr(Meta::new(MetaType::NfProto))
                .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV6 as u8]))
                .with_expr(Masquerade::default());
            batch.add(&lan_masq, MsgType::Add);
        }

        batch
            .send()
            .map_err(|e| NatError::Nftables(e.to_string()))?;
        Ok(())
    }
}
