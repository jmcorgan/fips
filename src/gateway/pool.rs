//! Virtual IP pool manager.
//!
//! Manages allocation, TTL, and reclamation of virtual IPv6 addresses
//! from a configured CIDR range. Tracks mapping state and integrates
//! with conntrack to determine active sessions.

use crate::NodeAddr;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv6Addr;
use std::time::Instant;
use tracing::{debug, info};

/// Errors from pool operations.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("invalid CIDR: {0}")]
    InvalidCidr(String),
    #[error("pool exhausted ({0} addresses in use)")]
    Exhausted(usize),
    #[error("prefix length must be between 1 and 128")]
    InvalidPrefix,
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

/// Trait for querying conntrack session counts.
pub trait ConntrackQuerier: Send + Sync {
    /// Returns the number of active conntrack entries whose original
    /// destination matches the given virtual IP.
    fn active_sessions(&self, virtual_ip: Ipv6Addr) -> Result<u32, std::io::Error>;
}

/// Conntrack querier that parses /proc/net/nf_conntrack.
pub struct ProcConntrack;

impl ConntrackQuerier for ProcConntrack {
    fn active_sessions(&self, virtual_ip: Ipv6Addr) -> Result<u32, std::io::Error> {
        let content = std::fs::read_to_string("/proc/net/nf_conntrack")?;
        let target = virtual_ip.to_string();
        let count = content
            .lines()
            .filter(|line| line.contains(&format!("dst={target}")))
            .count();
        Ok(count as u32)
    }
}

/// Virtual IP pool manager.
pub struct VirtualIpPool {
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
}

impl VirtualIpPool {
    /// Create a new pool from a CIDR string (e.g., `fd01::/112`).
    pub fn new(cidr: &str, ttl_secs: u64, grace_secs: u64) -> Result<Self, PoolError> {
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
            available,
            mappings: HashMap::new(),
            reverse: HashMap::new(),
            ttl_secs,
            grace_secs,
            total,
        })
    }

    /// Allocate a virtual IP for the given node. Idempotent: returns
    /// existing mapping if one exists.
    pub fn allocate(
        &mut self,
        node_addr: NodeAddr,
        mesh_addr: Ipv6Addr,
        dns_name: &str,
    ) -> Result<(Ipv6Addr, bool), PoolError> {
        // Idempotent: return existing mapping
        if let Some(mapping) = self.mappings.get_mut(&node_addr) {
            mapping.last_referenced = Instant::now();
            return Ok((mapping.virtual_ip, false));
        }

        let virtual_ip = self
            .available
            .pop_front()
            .ok_or(PoolError::Exhausted(self.mappings.len()))?;

        let now = Instant::now();
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

        Ok((virtual_ip, true))
    }

    /// Periodic tick — drives state transitions. Returns events for
    /// the NAT and network modules.
    pub fn tick(&mut self, now: Instant, conntrack: &dyn ConntrackQuerier) -> Vec<PoolEvent> {
        let mut events = Vec::new();
        let mut to_free = Vec::new();
        let ttl = std::time::Duration::from_secs(self.ttl_secs);
        let grace = std::time::Duration::from_secs(self.grace_secs);

        for (node_addr, mapping) in &mut self.mappings {
            // Query conntrack for active sessions
            let sessions = conntrack.active_sessions(mapping.virtual_ip).unwrap_or(0);
            mapping.session_count = sessions;

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
                    if now.duration_since(mapping.last_referenced) > ttl {
                        if sessions > 0 {
                            mapping.state = MappingState::Draining;
                            mapping.drain_start = Some(now);
                            debug!(
                                virtual_ip = %mapping.virtual_ip,
                                sessions,
                                "Mapping draining (TTL expired, sessions active)"
                            );
                        } else {
                            // TTL expired and no sessions — start grace
                            mapping.state = MappingState::Draining;
                            mapping.drain_start = Some(now);
                            mapping.session_count = 0;
                        }
                    }
                }
                MappingState::Draining => {
                    if sessions == 0
                        && let Some(drain_start) = mapping.drain_start
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

    /// Mock conntrack that returns a configurable session count.
    struct MockConntrack {
        counts: HashMap<Ipv6Addr, u32>,
    }

    impl MockConntrack {
        fn new() -> Self {
            Self {
                counts: HashMap::new(),
            }
        }

        fn set(&mut self, addr: Ipv6Addr, count: u32) {
            self.counts.insert(addr, count);
        }
    }

    impl ConntrackQuerier for MockConntrack {
        fn active_sessions(&self, virtual_ip: Ipv6Addr) -> Result<u32, std::io::Error> {
            Ok(*self.counts.get(&virtual_ip).unwrap_or(&0))
        }
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

        let (vip, is_new) = pool.allocate(node, mesh, "test.fips").unwrap();
        assert!(is_new);
        assert_eq!(vip, "fd01::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(pool.available.len(), 254);
    }

    #[test]
    fn test_pool_idempotent() {
        let mut pool = VirtualIpPool::new("fd01::/120", 60, 60).unwrap();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);

        let (vip1, new1) = pool.allocate(node, mesh, "test.fips").unwrap();
        let (vip2, new2) = pool.allocate(node, mesh, "test.fips").unwrap();
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

    #[test]
    fn test_mapping_lifecycle_allocated_to_free() {
        let mut pool = VirtualIpPool::new("fd01::/120", 1, 1).unwrap();
        let ct = MockConntrack::new();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);

        pool.allocate(node, mesh, "test.fips").unwrap();

        // Tick before TTL — no change
        let now = Instant::now();
        let events = pool.tick(now, &ct);
        assert!(events.is_empty());
        assert_eq!(pool.mappings.len(), 1);

        // Tick after TTL with no sessions — enters draining
        let later = now + std::time::Duration::from_secs(2);
        let events = pool.tick(later, &ct);
        assert!(events.is_empty());
        assert_eq!(pool.mappings.len(), 1);
        assert_eq!(
            pool.mappings.values().next().unwrap().state,
            MappingState::Draining
        );

        // Tick after grace period — freed
        let after_grace = later + std::time::Duration::from_secs(2);
        let events = pool.tick(after_grace, &ct);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], PoolEvent::MappingRemoved { .. }));
        assert_eq!(pool.mappings.len(), 0);
        assert_eq!(pool.available.len(), 255); // returned to pool
    }

    #[test]
    fn test_mapping_lifecycle_active_draining_free() {
        let mut pool = VirtualIpPool::new("fd01::/120", 1, 1).unwrap();
        let mut ct = MockConntrack::new();
        let node = make_node_addr(1);
        let mesh = make_mesh_addr(1);

        let (vip, _) = pool.allocate(node, mesh, "test.fips").unwrap();

        // Simulate active sessions
        ct.set(vip, 3);
        let now = Instant::now();
        let events = pool.tick(now, &ct);
        assert!(events.is_empty());
        assert_eq!(pool.mappings[&node].state, MappingState::Active);

        // TTL expires but sessions remain → Draining
        let later = now + std::time::Duration::from_secs(2);
        ct.set(vip, 1);
        let events = pool.tick(later, &ct);
        assert!(events.is_empty());
        assert_eq!(pool.mappings[&node].state, MappingState::Draining);

        // Sessions drop to 0 but grace period not elapsed
        ct.set(vip, 0);
        let events = pool.tick(later, &ct);
        assert!(events.is_empty());
        assert_eq!(pool.mappings[&node].state, MappingState::Draining);

        // Grace period elapsed → Free
        let much_later = later + std::time::Duration::from_secs(2);
        let events = pool.tick(much_later, &ct);
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

        let (vip, _) = pool.allocate(node, mesh, "test.fips").unwrap();
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
}
