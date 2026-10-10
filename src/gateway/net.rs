//! Network setup for the gateway.
//!
//! Manages proxy NDP entries and routes for the virtual IP range.
//! Checks IP forwarding prerequisites.

use super::nat::{RetryLog, RetryReport};
use std::net::Ipv6Addr;
use tracing::{debug, error, info, warn};

/// Check if IPv6 forwarding is enabled.
///
/// The gateway is completely non-functional without forwarding — packets
/// cannot traverse the NAT pipeline. Exits the process on failure.
pub fn check_ipv6_forwarding() {
    match std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding") {
        Ok(val) if val.trim() == "1" => {
            debug!("IPv6 forwarding is enabled");
        }
        Ok(_) => {
            error!(
                "IPv6 forwarding is disabled. Enable with: \
                 sysctl -w net.ipv6.conf.all.forwarding=1"
            );
            std::process::exit(1);
        }
        Err(e) => {
            error!(error = %e, "Could not check IPv6 forwarding state");
            std::process::exit(1);
        }
    }
}

/// Check that a network interface exists using rtnetlink.
pub async fn check_interface_exists(name: &str) -> Result<u32, std::io::Error> {
    let index = rustables::iface_index(name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?;
    debug!(interface = %name, index, "Interface found");
    Ok(index)
}

/// Manages proxy NDP entries and routes for gateway virtual IPs.
pub struct NetSetup {
    lan_interface: String,
    /// Proxy NDP entries added during this run (for cleanup).
    proxy_entries: Vec<Ipv6Addr>,
    /// Whether a route was added for the pool range.
    route_added: bool,
    pool_cidr: String,
}

impl NetSetup {
    /// Create a new network setup manager.
    pub fn new(lan_interface: String, pool_cidr: String) -> Self {
        Self {
            lan_interface,
            proxy_entries: Vec::new(),
            route_added: false,
            pool_cidr,
        }
    }

    /// Add a local route for the virtual IP pool range.
    ///
    /// The `local` route tells the kernel to accept packets destined for
    /// addresses in the pool as locally-owned, enabling NAT processing.
    /// Uses `dev lo` because local routes don't need to reference the LAN
    /// interface — the kernel matches on the routing table regardless of
    /// which interface the packet arrives on.
    pub async fn add_pool_route(&mut self) -> Result<(), std::io::Error> {
        let output = tokio::process::Command::new("ip")
            .args(["-6", "route", "add", "local", &self.pool_cidr, "dev", "lo"])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // "File exists" means route already present — not an error
            if stderr.contains("File exists") {
                debug!(cidr = %self.pool_cidr, "Pool route already exists");
                return Ok(());
            }
            return Err(std::io::Error::other(format!(
                "Failed to add pool route: {stderr}"
            )));
        }

        self.route_added = true;
        info!(cidr = %self.pool_cidr, "Added local pool route");
        Ok(())
    }

    /// Add a proxy NDP entry for a virtual IP on the LAN interface.
    pub async fn add_proxy_ndp(&mut self, addr: Ipv6Addr) -> Result<(), std::io::Error> {
        let addr_str = addr.to_string();
        let output = tokio::process::Command::new("ip")
            .args([
                "-6",
                "neigh",
                "add",
                "proxy",
                &addr_str,
                "dev",
                &self.lan_interface,
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("File exists") {
                debug!(addr = %addr, "Proxy NDP entry already exists");
                return Ok(());
            }
            return Err(std::io::Error::other(format!(
                "Failed to add proxy NDP: {stderr}"
            )));
        }

        self.proxy_entries.push(addr);
        debug!(addr = %addr, iface = %self.lan_interface, "Added proxy NDP entry");
        Ok(())
    }

    /// Remove a proxy NDP entry.
    pub async fn remove_proxy_ndp(&mut self, addr: Ipv6Addr) -> Result<(), std::io::Error> {
        let addr_str = addr.to_string();
        let output = tokio::process::Command::new("ip")
            .args([
                "-6",
                "neigh",
                "del",
                "proxy",
                &addr_str,
                "dev",
                &self.lan_interface,
            ])
            .output()
            .await?;

        self.proxy_entries.retain(|a| *a != addr);
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // "No such file": the entry was already gone.
            if !stderr.contains("No such file") {
                return Err(std::io::Error::other(format!(
                    "Failed to remove proxy NDP: {}",
                    stderr.trim()
                )));
            }
        }
        Ok(())
    }

    /// Clean up all proxy NDP entries and routes added during this run.
    pub async fn cleanup(&mut self) {
        // Remove proxy NDP entries, with one line for all failures.
        let entries: Vec<Ipv6Addr> = self.proxy_entries.clone();
        let mut failed = 0usize;
        let mut last_error = None;
        for addr in entries {
            if let Err(e) = self.remove_proxy_ndp(addr).await {
                failed += 1;
                last_error = Some(e);
            }
        }
        if let Some(e) = last_error {
            warn!(failed, error = %e, "Failed to remove proxy NDP entries at shutdown");
        }

        // Remove pool route
        if self.route_added {
            let output = tokio::process::Command::new("ip")
                .args(["-6", "route", "del", "local", &self.pool_cidr, "dev", "lo"])
                .output()
                .await;

            match output {
                Ok(o) if o.status.success() => {
                    info!(cidr = %self.pool_cidr, "Removed pool route");
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    warn!(error = %stderr.trim(), "Failed to remove pool route");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to run ip route del");
                }
            }
            self.route_added = false;
        }
    }
}

/// Proxy NDP outcomes, latched per direction.
///
/// Each added entry comes from a LAN host naming a new name, and with
/// eviction each also brings a removal, so a persistent `ip -6 neigh` failure
/// would otherwise log a line per name. An error that names its address
/// counts as the same error for every address.
#[derive(Debug, Default)]
pub struct NdpLog {
    add: RetryLog,
    remove: RetryLog,
}

impl NdpLog {
    /// Record the outcome of adding the entry for `addr`.
    pub fn observe_add(
        &mut self,
        addr: Ipv6Addr,
        result: &Result<(), std::io::Error>,
    ) -> RetryReport {
        self.add.observe_message(failure_text(addr, result))
    }

    /// Record the outcome of removing the entry for `addr`.
    pub fn observe_remove(
        &mut self,
        addr: Ipv6Addr,
        result: &Result<(), std::io::Error>,
    ) -> RetryReport {
        self.remove.observe_message(failure_text(addr, result))
    }
}

/// A failure's text with `addr`'s own text taken out.
fn failure_text(addr: Ipv6Addr, result: &Result<(), std::io::Error>) -> Option<String> {
    result
        .as_ref()
        .err()
        .map(|e| e.to_string().replace(&addr.to_string(), "<addr>"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(addr: Ipv6Addr, why: &str) -> Result<(), std::io::Error> {
        Err(std::io::Error::other(format!(
            "Failed to add proxy NDP: {why} for {addr}"
        )))
    }

    #[test]
    fn proxy_ndp_failures_log_once_per_change_of_outcome() {
        let mut log = NdpLog::default();
        let addrs: Vec<Ipv6Addr> = (1..=10u16)
            .map(|i| Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, i))
            .collect();

        let reports: Vec<RetryReport> = addrs
            .iter()
            .map(|a| {
                log.observe_add(
                    *a,
                    &failure(*a, "RTNETLINK answers: Operation not permitted"),
                )
            })
            .collect();
        assert_eq!(reports[0], RetryReport::Failed);
        assert!(
            reports[1..].iter().all(|r| *r == RetryReport::Repeated),
            "an error naming its address must not count as a new error per name: {reports:?}"
        );

        // Removal keeps its own latch: its first failure is reported even
        // while the same error is latched for adds.
        assert_eq!(
            log.observe_remove(
                addrs[3],
                &failure(addrs[3], "RTNETLINK answers: Operation not permitted")
            ),
            RetryReport::Failed
        );

        assert_eq!(
            log.observe_add(
                addrs[0],
                &failure(addrs[0], "RTNETLINK answers: No buffer space")
            ),
            RetryReport::Failed,
            "a different error is a new outcome"
        );
        assert_eq!(log.observe_add(addrs[1], &Ok(())), RetryReport::Recovered);
        assert_eq!(log.observe_add(addrs[2], &Ok(())), RetryReport::Clean);
    }
}
