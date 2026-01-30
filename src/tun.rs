//! FIPS TUN Interface
//!
//! Manages the TUN device for sending and receiving IPv6 packets.
//! The TUN interface presents FIPS addresses to the local system,
//! allowing standard socket applications to communicate over the mesh.

use crate::{FipsAddress, TunConfig};
use futures::TryStreamExt;
use rtnetlink::{new_connection, Handle};
use std::fs::File;
use std::io::{Read, Write};
use std::net::Ipv6Addr;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::mpsc;
use thiserror::Error;
use tracing::{debug, error, info};
use tun::Layer;

/// Channel sender for packets to be written to TUN.
pub type TunTx = mpsc::Sender<Vec<u8>>;

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
    /// Create or open a TUN device.
    ///
    /// If the interface already exists, opens it and reconfigures it.
    /// Otherwise, creates a new TUN device.
    ///
    /// This requires CAP_NET_ADMIN capability (run with sudo or setcap).
    pub async fn create(config: &TunConfig, address: FipsAddress) -> Result<Self, TunError> {
        // Check if IPv6 is enabled
        if is_ipv6_disabled() {
            return Err(TunError::Ipv6Disabled);
        }

        let name = config.name();
        let mtu = config.mtu();

        // Delete existing interface if present (TUN devices are exclusive)
        if interface_exists(name).await {
            info!(name, "Deleting existing TUN interface");
            if let Err(e) = delete_interface(name).await {
                debug!(name, error = %e, "Failed to delete existing interface");
            }
        }

        // Create the TUN device
        let mut tun_config = tun::Configuration::default();

        #[allow(deprecated)]
        tun_config.name(name).layer(Layer::L3).mtu(mtu);

        let device = tun::create(&tun_config)?;

        // Configure address and bring up via netlink
        configure_interface(name, address.to_ipv6(), mtu).await?;

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

    /// Read a packet from the TUN device.
    ///
    /// Returns the number of bytes read into the buffer, or an error.
    /// The buffer should be at least MTU + header size (typically 1500+ bytes).
    pub fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        self.device.read(buf).map_err(|e| TunError::Configure(format!("read failed: {}", e)))
    }

    /// Shutdown and delete the TUN device.
    ///
    /// This deletes the interface entirely.
    pub async fn shutdown(&self) -> Result<(), TunError> {
        info!(name = %self.name, "Deleting TUN device");
        delete_interface(&self.name).await
    }

    /// Create a TunWriter for this device.
    ///
    /// This duplicates the underlying file descriptor so that reads and writes
    /// can happen independently on separate threads. Returns the writer and
    /// a channel sender for submitting packets to be written.
    pub fn create_writer(&self) -> Result<(TunWriter, TunTx), TunError> {
        let fd = self.device.as_raw_fd();

        // Duplicate the file descriptor for writing
        let write_fd = unsafe { libc::dup(fd) };
        if write_fd < 0 {
            return Err(TunError::Configure(format!(
                "failed to dup fd: {}",
                std::io::Error::last_os_error()
            )));
        }

        let write_file = unsafe { File::from_raw_fd(write_fd) };
        let (tx, rx) = mpsc::channel();

        Ok((
            TunWriter {
                file: write_file,
                rx,
                name: self.name.clone(),
            },
            tx,
        ))
    }
}

/// Writer thread for TUN device.
///
/// Services a queue of outbound packets and writes them to the TUN device.
/// Multiple producers can send packets via the TunTx channel.
pub struct TunWriter {
    file: File,
    rx: mpsc::Receiver<Vec<u8>>,
    name: String,
}

impl TunWriter {
    /// Run the writer loop.
    ///
    /// Blocks forever, reading packets from the channel and writing them
    /// to the TUN device. Returns when the channel is closed (all senders dropped).
    pub fn run(mut self) {
        info!(name = %self.name, "TUN writer starting");

        for packet in self.rx {
            if let Err(e) = self.file.write_all(&packet) {
                // "Bad address" is expected during shutdown when interface is deleted
                let err_str = e.to_string();
                if err_str.contains("Bad address") {
                    info!(name = %self.name, "TUN interface deleted, writer stopping");
                    break;
                }
                error!(name = %self.name, error = %e, "TUN write error");
            } else {
                debug!(name = %self.name, len = packet.len(), "TUN packet written");
            }
        }

        info!(name = %self.name, "TUN writer stopped");
    }
}

/// Log basic information about an IPv6 packet at DEBUG level.
pub fn log_ipv6_packet(packet: &[u8]) {
    if packet.len() < 40 {
        debug!(len = packet.len(), "Received undersized packet");
        return;
    }

    let version = packet[0] >> 4;
    if version != 6 {
        debug!(version, len = packet.len(), "Received non-IPv6 packet");
        return;
    }

    let payload_len = u16::from_be_bytes([packet[4], packet[5]]);
    let next_header = packet[6];
    let hop_limit = packet[7];

    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());

    let protocol = match next_header {
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "other",
    };

    debug!(
        %src,
        %dst,
        protocol,
        next_header,
        payload_len,
        hop_limit,
        total_len = packet.len(),
        "TUN packet received"
    );
}

/// Shutdown and delete a TUN interface by name.
///
/// This deletes the interface, which will cause any blocking reads
/// to return an error. Use this for graceful shutdown when the TUN device
/// has been moved to another thread.
pub async fn shutdown_tun_interface(name: &str) -> Result<(), TunError> {
    info!(name, "shutdown_tun_interface called");
    delete_interface(name).await
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

/// Check if a network interface already exists.
async fn interface_exists(name: &str) -> bool {
    let Ok((connection, handle, _)) = new_connection() else {
        return false;
    };
    tokio::spawn(connection);

    get_interface_index(&handle, name).await.is_ok()
}

/// Delete a network interface by name.
async fn delete_interface(name: &str) -> Result<(), TunError> {
    info!(name, "delete_interface: starting");
    let (connection, handle, _) = new_connection()
        .map_err(|e| TunError::Configure(format!("netlink connection failed: {}", e)))?;
    tokio::spawn(connection);

    let index = get_interface_index(&handle, name).await?;
    info!(name, index, "delete_interface: got index, deleting");
    handle.link().del(index).execute().await?;

    info!(name, "delete_interface: done");
    Ok(())
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
