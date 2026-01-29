//! FIPS TUN Interface
//!
//! Manages the TUN device for sending and receiving IPv6 packets.
//! The TUN interface presents FIPS addresses to the local system,
//! allowing standard socket applications to communicate over the mesh.

use crate::{FipsAddress, TunConfig};
use futures::TryStreamExt;
use rtnetlink::{new_connection, Handle};
use std::net::Ipv6Addr;
use thiserror::Error;
use tun::Layer;

/// Errors that can occur with TUN operations.
#[derive(Debug, Error)]
pub enum TunError {
    #[error("failed to create TUN device: {0}")]
    Create(#[from] tun::Error),

    #[error("failed to configure TUN device: {0}")]
    Configure(String),

    #[error("netlink error: {0}")]
    Netlink(#[from] rtnetlink::Error),

    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("IPv6 is disabled (set net.ipv6.conf.all.disable_ipv6=0)")]
    Ipv6Disabled,
}

/// TUN device state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunState {
    /// TUN is disabled in configuration.
    Disabled,
    /// TUN is configured but not yet created.
    Configured,
    /// TUN device is active and ready.
    Active,
    /// TUN device failed to initialize.
    Failed,
}

impl std::fmt::Display for TunState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunState::Disabled => write!(f, "disabled"),
            TunState::Configured => write!(f, "configured"),
            TunState::Active => write!(f, "active"),
            TunState::Failed => write!(f, "failed"),
        }
    }
}

/// FIPS TUN device wrapper.
pub struct TunDevice {
    device: tun::Device,
    name: String,
    mtu: u16,
    address: FipsAddress,
}

impl TunDevice {
    /// Create and configure a new TUN device.
    ///
    /// This requires CAP_NET_ADMIN capability (run with sudo or setcap).
    pub async fn create(config: &TunConfig, address: FipsAddress) -> Result<Self, TunError> {
        // Check if IPv6 is enabled
        if is_ipv6_disabled() {
            return Err(TunError::Ipv6Disabled);
        }

        let name = config.name();
        let mtu = config.mtu();

        // Create the TUN device without address (we'll set it via netlink)
        let mut tun_config = tun::Configuration::default();

        #[allow(deprecated)]
        tun_config.name(name).layer(Layer::L3).mtu(mtu);

        let device = tun::create(&tun_config)?;

        // Configure address and bring up via netlink
        if let Err(e) = configure_interface(name, address.to_ipv6(), mtu).await {
            // If netlink fails, the device was created but not configured.
            // Drop will clean up the device.
            return Err(e);
        }

        Ok(Self {
            device,
            name: name.to_string(),
            mtu,
            address,
        })
    }

    /// Get the device name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the configured MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Get the FIPS address assigned to this device.
    pub fn address(&self) -> &FipsAddress {
        &self.address
    }

    /// Get a reference to the underlying tun::Device.
    pub fn device(&self) -> &tun::Device {
        &self.device
    }

    /// Get a mutable reference to the underlying tun::Device.
    pub fn device_mut(&mut self) -> &mut tun::Device {
        &mut self.device
    }
}

impl std::fmt::Debug for TunDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunDevice")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .field("address", &self.address)
            .finish()
    }
}

/// Configure a network interface with an IPv6 address via netlink.
async fn configure_interface(name: &str, addr: Ipv6Addr, mtu: u16) -> Result<(), TunError> {
    let (connection, handle, _) = new_connection()
        .map_err(|e| TunError::Configure(format!("netlink connection failed: {}", e)))?;
    tokio::spawn(connection);

    // Get interface index
    let index = get_interface_index(&handle, name).await?;

    // Add IPv6 address with /128 prefix (point-to-point)
    handle
        .address()
        .add(index, std::net::IpAddr::V6(addr), 128)
        .execute()
        .await?;

    // Set MTU
    handle
        .link()
        .set(index)
        .mtu(mtu as u32)
        .execute()
        .await?;

    // Bring interface up
    handle.link().set(index).up().execute().await?;

    Ok(())
}

/// Get the interface index by name.
async fn get_interface_index(handle: &Handle, name: &str) -> Result<u32, TunError> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();

    if let Some(link) = links.try_next().await? {
        Ok(link.header.index)
    } else {
        Err(TunError::InterfaceNotFound(name.to_string()))
    }
}

/// Check if IPv6 is disabled system-wide.
fn is_ipv6_disabled() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_state_display() {
        assert_eq!(format!("{}", TunState::Disabled), "disabled");
        assert_eq!(format!("{}", TunState::Active), "active");
    }

    // Note: TUN device creation tests require elevated privileges
    // and are better suited for integration tests.
}
