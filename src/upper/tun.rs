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
use tracing::{debug, error, info, trace};
use tun::Layer;

/// Channel sender for packets to be written to TUN.
pub type TunTx = mpsc::Sender<Vec<u8>>;

/// Channel sender for outbound packets from TUN reader to Node.
pub type TunOutboundTx = tokio::sync::mpsc::Sender<Vec<u8>>;
/// Channel receiver for outbound packets (consumed by Node's RX loop).
pub type TunOutboundRx = tokio::sync::mpsc::Receiver<Vec<u8>>;

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
    ///
    /// The max_mss parameter is used for TCP MSS clamping on inbound packets.
    pub fn create_writer(&self, max_mss: u16) -> Result<(TunWriter, TunTx), TunError> {
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
                max_mss,
            },
            tx,
        ))
    }
}

/// Writer thread for TUN device.
///
/// Services a queue of outbound packets and writes them to the TUN device.
/// Multiple producers can send packets via the TunTx channel.
///
/// Also performs TCP MSS clamping on inbound SYN-ACK packets.
pub struct TunWriter {
    file: File,
    rx: mpsc::Receiver<Vec<u8>>,
    name: String,
    max_mss: u16,
}

impl TunWriter {
    /// Run the writer loop.
    ///
    /// Blocks forever, reading packets from the channel and writing them
    /// to the TUN device. Returns when the channel is closed (all senders dropped).
    pub fn run(mut self) {
        use super::tcp_mss::clamp_tcp_mss;

        debug!(name = %self.name, max_mss = self.max_mss, "TUN writer starting");

        for mut packet in self.rx {
            // Clamp TCP MSS on inbound SYN-ACK packets
            if clamp_tcp_mss(&mut packet, self.max_mss) {
                trace!(
                    name = %self.name,
                    max_mss = self.max_mss,
                    "Clamped TCP MSS in inbound SYN-ACK packet"
                );
            }

            if let Err(e) = self.file.write_all(&packet) {
                // "Bad address" is expected during shutdown when interface is deleted
                let err_str = e.to_string();
                if err_str.contains("Bad address") {
                    break;
                }
                error!(name = %self.name, error = %e, "TUN write error");
            } else {
                trace!(name = %self.name, len = packet.len(), "TUN packet written");
            }
        }
    }
}

/// TUN packet reader loop.
///
/// Reads IPv6 packets from the TUN device. Packets destined for FIPS addresses
/// (fd::/8) are forwarded to the Node via the outbound channel for session
/// encapsulation and routing. Non-FIPS packets receive ICMPv6 Destination
/// Unreachable responses.
///
/// Also performs TCP MSS clamping on SYN packets to prevent oversized segments.
///
/// This is designed to run in a dedicated thread since TUN reads are blocking.
/// The loop exits when the TUN interface is deleted (EFAULT) or an unrecoverable
/// error occurs.
pub fn run_tun_reader(
    mut device: TunDevice,
    mtu: u16,
    our_addr: FipsAddress,
    tun_tx: TunTx,
    outbound_tx: TunOutboundTx,
    transport_mtu: u16,
) {
    use super::icmp::{build_dest_unreachable, effective_ipv6_mtu, should_send_icmp_error, DestUnreachableCode};
    use super::tcp_mss::clamp_tcp_mss;

    let name = device.name().to_string();
    let mut buf = vec![0u8; mtu as usize + 100]; // Extra space for headers

    // Calculate maximum safe TCP MSS from the effective IPv6 MTU
    const IPV6_HEADER: u16 = 40;
    const TCP_HEADER: u16 = 20;
    let effective_mtu = effective_ipv6_mtu(transport_mtu);
    let max_mss = effective_mtu
        .saturating_sub(IPV6_HEADER)
        .saturating_sub(TCP_HEADER);

    debug!(
        name = %name,
        tun_mtu = mtu,
        transport_mtu = transport_mtu,
        effective_mtu = effective_mtu,
        max_mss = max_mss,
        "TUN reader starting"
    );

    loop {
        match device.read_packet(&mut buf) {
            Ok(n) if n > 0 => {
                let packet = &mut buf[..n];
                log_ipv6_packet(packet);

                // Must be a valid IPv6 packet
                if packet.len() < 40 || packet[0] >> 4 != 6 {
                    continue;
                }

                // Check if destination is a FIPS address (fd::/8 prefix)
                if packet[24] == crate::identity::FIPS_ADDRESS_PREFIX {
                    // Clamp TCP MSS if this is a SYN packet
                    if clamp_tcp_mss(packet, max_mss) {
                        trace!(
                            name = %name,
                            max_mss = max_mss,
                            "Clamped TCP MSS in SYN packet"
                        );
                    }

                    // Forward to Node for session encapsulation and routing
                    if outbound_tx.blocking_send(packet.to_vec()).is_err() {
                        break; // Channel closed, shutdown
                    }
                } else {
                    // Non-FIPS destination: send ICMPv6 Destination Unreachable
                    if should_send_icmp_error(packet)
                        && let Some(response) = build_dest_unreachable(
                            packet,
                            DestUnreachableCode::NoRoute,
                            our_addr.to_ipv6(),
                        )
                    {
                        trace!(
                            name = %name,
                            len = response.len(),
                            "Sending ICMPv6 Destination Unreachable (non-FIPS destination)"
                        );
                        if tun_tx.send(response).is_err() {
                            break;
                        }
                    }
                }
            }
            Ok(_) => {
                // Zero-length read, continue
            }
            Err(e) => {
                // "Bad address" (EFAULT) is expected during shutdown when interface is deleted
                let err_str = format!("{}", e);
                if !err_str.contains("Bad address") {
                    error!(name = %name, error = %e, "TUN read error");
                }
                break;
            }
        }
    }
}

/// Log basic information about an IPv6 packet at TRACE level.
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

    trace!("TUN packet received:");
    trace!("      src: {}", src);
    trace!("      dst: {}", dst);
    trace!(" protocol: {} ({})", protocol, next_header);
    trace!("  payload: {} bytes, hop_limit: {}", payload_len, hop_limit);
}

/// Shutdown and delete a TUN interface by name.
///
/// This deletes the interface, which will cause any blocking reads
/// to return an error. Use this for graceful shutdown when the TUN device
/// has been moved to another thread.
pub async fn shutdown_tun_interface(name: &str) -> Result<(), TunError> {
    info!("Shutting down TUN interface {}", name);
    delete_interface(name).await?;
    info!("TUN interface {} stopped", name);
    Ok(())
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
    let (connection, handle, _) = new_connection()
        .map_err(|e| TunError::Configure(format!("netlink connection failed: {}", e)))?;
    tokio::spawn(connection);

    let index = get_interface_index(&handle, name).await?;
    handle.link().del(index).execute().await?;
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

    // Add route for fd00::/8 (FIPS address space) via this interface
    let fd_prefix: Ipv6Addr = "fd00::".parse().unwrap();
    handle
        .route()
        .add()
        .v6()
        .destination_prefix(fd_prefix, 8)
        .output_interface(index)
        .execute()
        .await
        .map_err(|e| TunError::Configure(format!("failed to add fd00::/8 route: {}", e)))?;

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
