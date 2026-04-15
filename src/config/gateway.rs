//! Gateway configuration types.
//!
//! Configuration for the outbound LAN gateway (`gateway.*`).

use std::collections::HashSet;
use std::net::SocketAddrV6;

use serde::{Deserialize, Serialize};

/// Default gateway DNS listen address.
const DEFAULT_DNS_LISTEN: &str = "[::]:53";

/// Default upstream DNS resolver (FIPS daemon).
const DEFAULT_DNS_UPSTREAM: &str = "127.0.0.1:5354";

/// Default DNS TTL in seconds.
const DEFAULT_DNS_TTL: u32 = 60;

/// Default pool grace period in seconds.
const DEFAULT_GRACE_PERIOD: u64 = 60;

/// Default conntrack TCP established timeout (5 days).
const DEFAULT_CT_TCP_ESTABLISHED: u64 = 432_000;

/// Default conntrack UDP timeout (unreplied).
const DEFAULT_CT_UDP_TIMEOUT: u64 = 30;

/// Default conntrack UDP assured timeout (bidirectional).
const DEFAULT_CT_UDP_ASSURED: u64 = 180;

/// Default conntrack ICMP timeout.
const DEFAULT_CT_ICMP_TIMEOUT: u64 = 30;

/// Gateway configuration (`gateway.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Enable the gateway (`gateway.enabled`, default: false).
    #[serde(default)]
    pub enabled: bool,

    /// Virtual IP pool CIDR (e.g., `fd01::/112`).
    pub pool: String,

    /// LAN-facing interface for proxy ARP/NDP.
    pub lan_interface: String,

    /// Gateway DNS configuration.
    #[serde(default)]
    pub dns: GatewayDnsConfig,

    /// Pool grace period in seconds after last session before reclamation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_grace_period: Option<u64>,

    /// Conntrack timeout overrides.
    #[serde(default)]
    pub conntrack: ConntrackConfig,

    /// Inbound mesh port forwarding rules. See TASK-2026-0061.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_forwards: Vec<PortForward>,
}

impl GatewayConfig {
    /// Get pool grace period (default: 60 seconds).
    pub fn grace_period(&self) -> u64 {
        self.pool_grace_period.unwrap_or(DEFAULT_GRACE_PERIOD)
    }

    /// Validate inbound port-forward rules: non-zero listen ports and
    /// uniqueness of `(listen_port, proto)` pairs across the list.
    /// IPv6-only targets are enforced by `SocketAddrV6` at deserialize
    /// time.
    pub fn validate_port_forwards(&self) -> Result<(), String> {
        let mut seen = HashSet::new();
        for pf in &self.port_forwards {
            if pf.listen_port == 0 {
                return Err("port_forward listen_port must be non-zero".to_string());
            }
            if !seen.insert((pf.listen_port, pf.proto)) {
                return Err(format!(
                    "duplicate port_forward ({:?} {}) — each (listen_port, proto) must be unique",
                    pf.proto, pf.listen_port
                ));
            }
        }
        Ok(())
    }
}

/// Transport protocol for an inbound port forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

/// An inbound port-forward rule: `fips0:listen_port/proto` → `target`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForward {
    /// Port on `fips0` that mesh peers connect to.
    pub listen_port: u16,
    /// Transport protocol to match.
    pub proto: Proto,
    /// IPv6 LAN destination (`[addr]:port`). IPv4 targets are rejected
    /// at parse time by `SocketAddrV6`.
    pub target: SocketAddrV6,
}

/// Gateway DNS resolver configuration (`gateway.dns.*`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatewayDnsConfig {
    /// Listen address and port (default: `0.0.0.0:53`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,

    /// Upstream FIPS daemon DNS resolver (default: `127.0.0.1:5354`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,

    /// DNS record TTL in seconds (default: 60).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

impl GatewayDnsConfig {
    /// Get the listen address (default: `0.0.0.0:53`).
    pub fn listen(&self) -> &str {
        self.listen.as_deref().unwrap_or(DEFAULT_DNS_LISTEN)
    }

    /// Get the upstream resolver address (default: `127.0.0.1:5354`).
    pub fn upstream(&self) -> &str {
        self.upstream.as_deref().unwrap_or(DEFAULT_DNS_UPSTREAM)
    }

    /// Get the TTL in seconds (default: 60).
    pub fn ttl(&self) -> u32 {
        self.ttl.unwrap_or(DEFAULT_DNS_TTL)
    }
}

/// Conntrack timeout overrides (`gateway.conntrack.*`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConntrackConfig {
    /// TCP established timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_established: Option<u64>,

    /// UDP unreplied timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<u64>,

    /// UDP assured (bidirectional) timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_assured: Option<u64>,

    /// ICMP timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icmp_timeout: Option<u64>,
}

impl ConntrackConfig {
    /// TCP established timeout (default: 432000s / 5 days).
    pub fn tcp_established(&self) -> u64 {
        self.tcp_established.unwrap_or(DEFAULT_CT_TCP_ESTABLISHED)
    }

    /// UDP unreplied timeout (default: 30s).
    pub fn udp_timeout(&self) -> u64 {
        self.udp_timeout.unwrap_or(DEFAULT_CT_UDP_TIMEOUT)
    }

    /// UDP assured timeout (default: 180s).
    pub fn udp_assured(&self) -> u64 {
        self.udp_assured.unwrap_or(DEFAULT_CT_UDP_ASSURED)
    }

    /// ICMP timeout (default: 30s).
    pub fn icmp_timeout(&self) -> u64 {
        self.icmp_timeout.unwrap_or(DEFAULT_CT_ICMP_TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_config_defaults() {
        let yaml = r#"
pool: "fd01::/112"
lan_interface: "eth0"
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.pool, "fd01::/112");
        assert_eq!(config.lan_interface, "eth0");
        assert_eq!(config.dns.listen(), "[::]:53");
        assert_eq!(config.dns.upstream(), "127.0.0.1:5354");
        assert_eq!(config.dns.ttl(), 60);
        assert_eq!(config.grace_period(), 60);
        assert_eq!(config.conntrack.tcp_established(), 432_000);
        assert_eq!(config.conntrack.udp_timeout(), 30);
    }

    #[test]
    fn test_gateway_config_custom() {
        let yaml = r#"
enabled: true
pool: "fd01::/112"
lan_interface: "enp3s0"
dns:
  listen: "192.168.1.1:53"
  upstream: "127.0.0.1:5354"
  ttl: 120
pool_grace_period: 30
conntrack:
  tcp_established: 3600
  udp_timeout: 60
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.dns.listen(), "192.168.1.1:53");
        assert_eq!(config.dns.ttl(), 120);
        assert_eq!(config.grace_period(), 30);
        assert_eq!(config.conntrack.tcp_established(), 3600);
        assert_eq!(config.conntrack.udp_timeout(), 60);
        // Unset fields use defaults
        assert_eq!(config.conntrack.udp_assured(), 180);
        assert_eq!(config.conntrack.icmp_timeout(), 30);
    }

    #[test]
    fn test_root_config_with_gateway() {
        let yaml = r#"
gateway:
  enabled: true
  pool: "fd01::/112"
  lan_interface: "eth0"
"#;
        let config: crate::Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.gateway.is_some());
        let gw = config.gateway.unwrap();
        assert!(gw.enabled);
        assert_eq!(gw.pool, "fd01::/112");
    }

    #[test]
    fn test_root_config_without_gateway() {
        let yaml = "node: {}";
        let config: crate::Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.gateway.is_none());
    }

    #[test]
    fn test_port_forwards_default_empty() {
        let yaml = r#"
pool: "fd01::/112"
lan_interface: "eth0"
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.port_forwards.is_empty());
        config.validate_port_forwards().unwrap();
    }

    #[test]
    fn test_port_forwards_parse() {
        let yaml = r#"
pool: "fd01::/112"
lan_interface: "eth0"
port_forwards:
  - listen_port: 8080
    proto: tcp
    target: "[fd12:3456::10]:80"
  - listen_port: 2222
    proto: tcp
    target: "[fd12:3456::20]:22"
  - listen_port: 5353
    proto: udp
    target: "[fd12:3456::10]:53"
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.port_forwards.len(), 3);
        assert_eq!(config.port_forwards[0].listen_port, 8080);
        assert_eq!(config.port_forwards[0].proto, Proto::Tcp);
        assert_eq!(
            config.port_forwards[0].target,
            "[fd12:3456::10]:80".parse::<SocketAddrV6>().unwrap()
        );
        assert_eq!(config.port_forwards[2].proto, Proto::Udp);
        config.validate_port_forwards().unwrap();
    }

    #[test]
    fn test_port_forwards_reject_ipv4_target() {
        let yaml = r#"
pool: "fd01::/112"
lan_interface: "eth0"
port_forwards:
  - listen_port: 8080
    proto: tcp
    target: "192.168.1.10:80"
"#;
        let result: Result<GatewayConfig, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_err(),
            "IPv4 target must fail to deserialize as SocketAddrV6"
        );
    }

    #[test]
    fn test_port_forwards_reject_zero_listen_port() {
        let yaml = r#"
pool: "fd01::/112"
lan_interface: "eth0"
port_forwards:
  - listen_port: 0
    proto: tcp
    target: "[fd12:3456::10]:80"
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate_port_forwards().is_err());
    }

    #[test]
    fn test_port_forwards_reject_duplicate() {
        let yaml = r#"
pool: "fd01::/112"
lan_interface: "eth0"
port_forwards:
  - listen_port: 8080
    proto: tcp
    target: "[fd12:3456::10]:80"
  - listen_port: 8080
    proto: tcp
    target: "[fd12:3456::20]:80"
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let err = config.validate_port_forwards().unwrap_err();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn test_port_forwards_same_port_different_proto_ok() {
        let yaml = r#"
pool: "fd01::/112"
lan_interface: "eth0"
port_forwards:
  - listen_port: 53
    proto: tcp
    target: "[fd12:3456::10]:53"
  - listen_port: 53
    proto: udp
    target: "[fd12:3456::10]:53"
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        config.validate_port_forwards().unwrap();
    }
}
