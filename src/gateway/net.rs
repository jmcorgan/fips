//! Network setup for the gateway.
//!
//! Manages proxy NDP entries and routes for the virtual IP range.
//! Checks IP forwarding prerequisites.

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

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Silently ignore "No such file" — entry may have been cleaned already
            if !stderr.contains("No such file") {
                warn!(addr = %addr, error = %stderr.trim(), "Failed to remove proxy NDP");
            }
        }

        self.proxy_entries.retain(|a| *a != addr);
        Ok(())
    }

    /// Clean up all proxy NDP entries and routes added during this run.
    pub async fn cleanup(&mut self) {
        // Remove proxy NDP entries
        let entries: Vec<Ipv6Addr> = self.proxy_entries.clone();
        for addr in entries {
            let _ = self.remove_proxy_ndp(addr).await;
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
