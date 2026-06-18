//! FIPS TUN Interface
//!
//! Manages the TUN device for sending and receiving IPv6 packets.
//! The TUN interface presents FIPS addresses to the local system,
//! allowing standard socket applications to communicate over the mesh.
//!
//! Platform-specific implementations:
//! - Linux: Uses the `tun` crate with `rtnetlink` for interface configuration
//! - macOS: Uses the `tun` crate with `ifconfig`/`route` for interface configuration
//! - Windows: Uses the `wintun` crate for TUN device support

#[cfg(windows)]
use crate::FipsAddress;
#[cfg(unix)]
use crate::{FipsAddress, TunConfig};
use std::collections::HashMap;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Read;
#[cfg(not(target_os = "macos"))]
#[cfg(unix)]
use std::io::Write;
use std::net::Ipv6Addr;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::{Arc, RwLock, mpsc};
use thiserror::Error;
#[cfg(unix)]
use tracing::error;
use tracing::{debug, trace};
#[cfg(windows)]
use tracing::{error, warn};
#[cfg(unix)]
use tun::Layer;

/// Read-only handle to the per-destination path MTU map. Populated by
/// the discovery handler on `LookupResponse`; read by the TUN reader
/// (outbound clamp) and writer (inbound clamp) at TCP MSS clamp time.
/// Keyed by [`FipsAddress`] (16 bytes, the IPv6 form of a fips peer
/// address).
pub type PathMtuLookup = Arc<RwLock<HashMap<FipsAddress, u16>>>;

/// Compute the effective TCP MSS ceiling for a packet given its peer
/// address bytes (a 16-byte IPv6 destination on outbound, source on
/// inbound). Returns `min(global_max_mss, learned_path_max_mss)` when
/// the per-destination path MTU is known via discovery; otherwise
/// returns `min(global_max_mss, ipv6_minimum_safe_max_mss)`, the
/// conservative IPv6-minimum-derived ceiling.
///
/// The conservative empty-lookup fallback exists because there is a
/// race window between TCP-SYN-out and discovery-completes-with-path-
/// MTU on cold flows. Without the floor, the first SYN exits at the
/// kernel-natural MSS (TUN MTU minus IPv6/TCP headers), which can
/// exceed what some downstream forwarder hop is willing to carry.
/// The drop is silent (no PTB feedback through the userspace TUN to
/// the kernel TCP stack), so TCP retransmits at the same too-large
/// MSS and the application's first connection wedges before discovery
/// completes for a corrected second SYN to fire.
///
/// RFC 8200 mandates every IPv6 path accepts at least 1280-byte
/// packets, so a SYN clamped to the IPv6-minimum-derived MSS fits
/// any compliant path. Subsequent flows pick up the actual learned
/// per-destination value, which can be larger (when path supports
/// it) or smaller (when path is observed-tighter than the IPv6 min).
///
/// Path MTU bytes-on-wire to TCP MSS: subtract 77 bytes of FIPS encap
/// overhead, then 40 bytes IPv6 + 20 bytes TCP headers.
pub(crate) fn per_flow_max_mss(
    lookup: &PathMtuLookup,
    addr_bytes: &[u8],
    global_max_mss: u16,
) -> u16 {
    use super::icmp::effective_ipv6_mtu;

    // RFC 8200 IPv6-minimum MTU (1280) → effective FIPS-encapsulated
    // payload (1203) → TCP segment after IPv6+TCP headers (1143).
    // Used as the conservative ceiling for empty-lookup destinations.
    const IPV6_MIN_MTU: u16 = 1280;
    let conservative_max_mss = effective_ipv6_mtu(IPV6_MIN_MTU)
        .saturating_sub(40)
        .saturating_sub(20);
    let empty_lookup_ceiling = std::cmp::min(global_max_mss, conservative_max_mss);

    if addr_bytes.len() != 16 {
        trace!(
            len = addr_bytes.len(),
            global_max_mss,
            empty_lookup_ceiling,
            "per_flow_max_mss: addr_bytes wrong length, fall back to conservative ceiling"
        );
        return empty_lookup_ceiling;
    }
    let Ok(fips_addr) = FipsAddress::from_slice(addr_bytes) else {
        trace!(
            global_max_mss,
            empty_lookup_ceiling,
            "per_flow_max_mss: FipsAddress::from_slice rejected (non-fd::/8 prefix), fall back to conservative ceiling"
        );
        return empty_lookup_ceiling;
    };
    let Ok(map) = lookup.read() else {
        trace!(
            fips_addr = %fips_addr,
            global_max_mss,
            empty_lookup_ceiling,
            "per_flow_max_mss: lookup read lock poisoned, fall back to conservative ceiling"
        );
        return empty_lookup_ceiling;
    };
    let Some(&path_mtu) = map.get(&fips_addr) else {
        trace!(
            fips_addr = %fips_addr,
            global_max_mss,
            empty_lookup_ceiling,
            map_len = map.len(),
            "per_flow_max_mss: no path_mtu_lookup entry for destination, fall back to conservative ceiling"
        );
        return empty_lookup_ceiling;
    };
    let path_max_mss = effective_ipv6_mtu(path_mtu)
        .saturating_sub(40)
        .saturating_sub(20);
    let result = std::cmp::min(global_max_mss, path_max_mss);
    trace!(
        fips_addr = %fips_addr,
        path_mtu,
        path_max_mss,
        global_max_mss,
        result,
        "per_flow_max_mss: per-destination clamp applied"
    );
    result
}

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
    Create(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to configure TUN device: {0}")]
    Configure(String),

    #[cfg(target_os = "linux")]
    #[error("netlink error: {0}")]
    Netlink(#[from] rtnetlink::Error),

    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[cfg(unix)]
    #[error("IPv6 is disabled (set net.ipv6.conf.all.disable_ipv6=0)")]
    Ipv6Disabled,
}

#[cfg(unix)]
impl From<tun::Error> for TunError {
    fn from(e: tun::Error) -> Self {
        TunError::Create(Box::new(e))
    }
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

// ============================================================================
// Unix (Linux + macOS) TUN implementation
// ============================================================================

/// FIPS TUN device wrapper.
#[cfg(unix)]
pub struct TunDevice {
    device: tun::Device,
    name: String,
    mtu: u16,
    address: FipsAddress,
}

#[cfg(unix)]
impl TunDevice {
    /// Create or open a TUN device.
    ///
    /// If the interface already exists, opens it and reconfigures it.
    /// Otherwise, creates a new TUN device.
    ///
    /// This requires CAP_NET_ADMIN capability (run with sudo or setcap).
    pub async fn create(config: &TunConfig, address: FipsAddress) -> Result<Self, TunError> {
        // Check if IPv6 is enabled
        if platform::is_ipv6_disabled() {
            return Err(TunError::Ipv6Disabled);
        }

        let name = config.name();
        let mtu = config.mtu();

        // Delete existing interface if present (TUN devices are exclusive)
        if platform::interface_exists(name).await {
            debug!(name, "Deleting existing TUN interface");
            if let Err(e) = platform::delete_interface(name).await {
                debug!(name, error = %e, "Failed to delete existing interface");
            }
        }

        // Create the TUN device
        let mut tun_config = tun::Configuration::default();

        // On macOS, utun devices get kernel-assigned names (utun0, utun1, ...),
        // so we skip setting the name and read it back after creation.
        #[cfg(target_os = "linux")]
        #[allow(deprecated)]
        tun_config.name(name).layer(Layer::L3).mtu(mtu);

        #[cfg(target_os = "macos")]
        {
            #[allow(deprecated)]
            tun_config.layer(Layer::L3).mtu(mtu);
        }

        let device = tun::create(&tun_config)?;

        // Read the actual device name (on macOS this is the kernel-assigned utun* name)
        let actual_name = {
            use tun::AbstractDevice;
            device
                .tun_name()
                .map_err(|e| TunError::Configure(format!("failed to get device name: {}", e)))?
        };

        // Configure address and bring up via platform-specific method
        platform::configure_interface(&actual_name, address.to_ipv6(), mtu).await?;

        Ok(Self {
            device,
            name: actual_name,
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
    /// Returns the number of bytes read into the buffer, or an `io::Error`.
    /// The buffer should be at least MTU + header size (typically 1500+ bytes).
    ///
    /// The tun crate's `Read` impl transparently strips the macOS utun
    /// packet information header, so this returns a raw IP packet on all
    /// platforms.
    ///
    /// The raw `io::Error` is returned so callers can inspect `ErrorKind`
    /// (e.g. `WouldBlock`) or `raw_os_error()` without string matching.
    pub fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.device.read(buf)
    }

    /// Shutdown and delete the TUN device.
    ///
    /// This deletes the interface entirely.
    pub async fn shutdown(&self) -> Result<(), TunError> {
        debug!(name = %self.name, "Deleting TUN device");
        platform::delete_interface(&self.name).await
    }

    /// Create a TunWriter for this device.
    ///
    /// This duplicates the underlying file descriptor so that reads and writes
    /// can happen independently on separate threads. Returns the writer and
    /// a channel sender for submitting packets to be written.
    ///
    /// `max_mss` is the global TCP MSS ceiling derived from the local
    /// `transport_mtu()` floor. `path_mtu_lookup` is a read-only handle to
    /// the per-destination path MTU map populated by discovery; the writer
    /// reads it on each inbound SYN-ACK to compute a per-flow ceiling that
    /// honors learned narrow paths through the mesh.
    pub fn create_writer(
        &self,
        max_mss: u16,
        path_mtu_lookup: PathMtuLookup,
    ) -> Result<(TunWriter, TunTx), TunError> {
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
                path_mtu_lookup,
            },
            tx,
        ))
    }
}

/// macOS utun protocol family value for IPv6 (matches `<sys/socket.h>`
/// `AF_INET6` on Darwin). Used as the 4-byte big-endian packet-info
/// header prepended to every utun frame.
#[cfg(target_os = "macos")]
const UTUN_AF_INET6: u32 = 30;

/// Build the 4-byte big-endian utun packet-info header for an IPv6 frame.
///
/// utun devices on macOS require a 4-byte address-family prefix on every
/// frame: a single big-endian `u32` carrying the protocol family. For
/// IPv6 traffic (the only family FIPS sends) this is `AF_INET6 = 30`,
/// which serializes as `[0x00, 0x00, 0x00, 0x1e]`.
#[cfg(target_os = "macos")]
#[inline]
fn utun_af_inet6_header() -> [u8; 4] {
    UTUN_AF_INET6.to_be_bytes()
}

/// Parse the 4-byte big-endian utun packet-info header.
///
/// Returns the address-family value (`AF_INET6 = 30` for IPv6 frames),
/// or `None` if the buffer is shorter than the 4-byte header. The `tun`
/// crate's `Read` impl strips this transparently for us in the read
/// path; this helper exists for round-trip testability with
/// [`utun_af_inet6_header`] and for any future code path that reads
/// from the dup'd fd directly.
#[cfg(target_os = "macos")]
#[inline]
#[allow(dead_code)]
fn parse_utun_af_prefix(buf: &[u8]) -> Option<u32> {
    if buf.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

/// Writer thread for TUN device.
///
/// Services a queue of outbound packets and writes them to the TUN device.
/// Multiple producers can send packets via the TunTx channel.
///
/// Also performs TCP MSS clamping on inbound SYN-ACK packets.
#[cfg(unix)]
pub struct TunWriter {
    file: File,
    rx: mpsc::Receiver<Vec<u8>>,
    name: String,
    max_mss: u16,
    path_mtu_lookup: PathMtuLookup,
}

#[cfg(unix)]
impl TunWriter {
    /// Run the writer loop.
    ///
    /// Blocks forever, reading packets from the channel and writing them
    /// to the TUN device. Returns when the channel is closed (all senders dropped).
    #[cfg_attr(target_os = "macos", allow(unused_mut))]
    pub fn run(mut self) {
        use super::tcp_mss::clamp_tcp_mss;

        debug!(name = %self.name, max_mss = self.max_mss, "TUN writer starting");

        for mut packet in self.rx {
            // Per-destination clamp: peer IPv6 source address (bytes 8..24)
            // identifies the flow's remote end. If discovery has learned a
            // smaller path MTU for that peer, tighten the ceiling.
            let effective_max_mss = if packet.len() >= 24 {
                per_flow_max_mss(&self.path_mtu_lookup, &packet[8..24], self.max_mss)
            } else {
                self.max_mss
            };
            // Clamp TCP MSS on inbound SYN-ACK packets
            if clamp_tcp_mss(&mut packet, effective_max_mss) {
                trace!(
                    name = %self.name,
                    max_mss = effective_max_mss,
                    "Clamped TCP MSS in inbound SYN-ACK packet"
                );
            }

            // On macOS, utun devices require a 4-byte packet information header
            // prepended to each packet. The tun crate handles this for its own
            // Read/Write impl, but we use a dup'd fd directly. We use writev
            // to avoid allocating a buffer on every packet.
            #[cfg(target_os = "macos")]
            let write_result = {
                use std::os::unix::io::AsRawFd;
                let af_header = utun_af_inet6_header();
                let iov = [
                    libc::iovec {
                        iov_base: af_header.as_ptr() as *mut libc::c_void,
                        iov_len: 4,
                    },
                    libc::iovec {
                        iov_base: packet.as_ptr() as *mut libc::c_void,
                        iov_len: packet.len(),
                    },
                ];
                let ret = unsafe { libc::writev(self.file.as_raw_fd(), iov.as_ptr(), 2) };
                if ret < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    let expected = 4 + packet.len();
                    if (ret as usize) < expected {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            format!("short writev: {} of {} bytes", ret, expected),
                        ))
                    } else {
                        Ok(())
                    }
                }
            };
            #[cfg(not(target_os = "macos"))]
            let write_result = self.file.write_all(&packet);

            if let Err(e) = write_result {
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

/// TUN packet reader loop (Linux).
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
#[cfg(not(target_os = "macos"))]
#[cfg(unix)]
pub fn run_tun_reader(
    mut device: TunDevice,
    mtu: u16,
    our_addr: FipsAddress,
    tun_tx: TunTx,
    outbound_tx: TunOutboundTx,
    transport_mtu: u16,
    path_mtu_lookup: PathMtuLookup,
) {
    let (name, mut buf, max_mss) = tun_reader_setup(device.name(), mtu, transport_mtu);

    loop {
        match device.read_packet(&mut buf) {
            Ok(n) if n > 0 => {
                if !handle_tun_packet(
                    &mut buf[..n],
                    max_mss,
                    &name,
                    our_addr,
                    &tun_tx,
                    &outbound_tx,
                    &path_mtu_lookup,
                ) {
                    break;
                }
            }
            Ok(_) => {}
            Err(e) => {
                // EFAULT ("Bad address") is expected during shutdown when the interface is deleted
                if e.raw_os_error() != Some(libc::EFAULT) {
                    error!(name = %name, error = %e, "TUN read error");
                }
                break;
            }
        }
    }
}

/// RAII wrapper that closes a raw fd on drop.
///
/// Used to ensure the shutdown pipe read-end is always closed when
/// `run_tun_reader` returns, regardless of which exit path is taken.
#[cfg(target_os = "macos")]
struct ShutdownFd(std::os::unix::io::RawFd);

#[cfg(target_os = "macos")]
impl Drop for ShutdownFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// TUN packet reader loop (macOS).
///
/// Uses `select()` to multiplex between the TUN fd and a shutdown pipe,
/// avoiding the need to close the TUN fd externally (which would cause a
/// double-close when `TunDevice` drops).
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
pub fn run_tun_reader(
    mut device: TunDevice,
    mtu: u16,
    our_addr: FipsAddress,
    tun_tx: TunTx,
    outbound_tx: TunOutboundTx,
    transport_mtu: u16,
    path_mtu_lookup: PathMtuLookup,
    shutdown_fd: std::os::unix::io::RawFd,
) {
    let _shutdown_fd = ShutdownFd(shutdown_fd);
    let tun_fd = device.device().as_raw_fd();
    let (name, mut buf, max_mss) = tun_reader_setup(device.name(), mtu, transport_mtu);

    // Set TUN fd to non-blocking so we can use select + read without blocking
    // past the point where select returns readable.
    unsafe {
        let flags = libc::fcntl(tun_fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(tun_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    let nfds = tun_fd.max(shutdown_fd) + 1;

    loop {
        // Wait for either TUN data or shutdown signal
        unsafe {
            let mut read_fds: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut read_fds);
            libc::FD_SET(tun_fd, &mut read_fds);
            libc::FD_SET(shutdown_fd, &mut read_fds);

            let ret = libc::select(
                nfds,
                &mut read_fds,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                error!(name = %name, error = %err, "TUN select error");
                break;
            }

            // Shutdown signal received
            if libc::FD_ISSET(shutdown_fd, &read_fds) {
                debug!(name = %name, "TUN reader received shutdown signal");
                break;
            }
        }

        // TUN fd is readable — drain all available packets
        loop {
            match device.read_packet(&mut buf) {
                Ok(n) if n > 0 => {
                    if !handle_tun_packet(
                        &mut buf[..n],
                        max_mss,
                        &name,
                        our_addr,
                        &tun_tx,
                        &outbound_tx,
                        &path_mtu_lookup,
                    ) {
                        return; // _shutdown_fd closes on drop
                    }
                }
                Ok(_) => break, // No more data
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break; // Done for this select round
                    }
                    // EBADF is expected during shutdown when the fd is closed
                    if e.raw_os_error() != Some(libc::EBADF) {
                        error!(name = %name, error = %e, "TUN read error");
                    }
                    return; // _shutdown_fd closes on drop
                }
            }
        }
    }
    // _shutdown_fd closes on drop
}

/// Common setup for TUN reader: allocates buffer, computes max MSS.
fn tun_reader_setup(device_name: &str, mtu: u16, transport_mtu: u16) -> (String, Vec<u8>, u16) {
    use super::icmp::effective_ipv6_mtu;

    let name = device_name.to_string();
    let buf = vec![0u8; mtu as usize + 100];

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

    (name, buf, max_mss)
}

/// Process a single TUN packet. Returns `false` if the reader should exit.
fn handle_tun_packet(
    packet: &mut [u8],
    max_mss: u16,
    name: &str,
    our_addr: FipsAddress,
    tun_tx: &TunTx,
    outbound_tx: &TunOutboundTx,
    path_mtu_lookup: &PathMtuLookup,
) -> bool {
    use super::icmp::{DestUnreachableCode, build_dest_unreachable, should_send_icmp_error};
    use super::tcp_mss::{clamp_tcp_mss, recalculate_l4_checksum};

    log_ipv6_packet(packet);

    // Must be a valid IPv6 packet
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return true;
    }

    // Check if destination is a FIPS address (fd::/8 prefix)
    if packet[24] == crate::identity::FIPS_ADDRESS_PREFIX {
        // Loopback: a packet to our own mesh address must be delivered
        // locally, not pushed into the mesh (we have no session/route to
        // ourselves, so it would just be dropped). Hairpin it back to the TUN
        // writer for inbound delivery.
        //
        // Platform note: in practice this branch is reached only on macOS.
        // macOS point-to-point `utun` interfaces egress self-addressed traffic
        // down the tunnel into this reader, so the daemon has to loop it back
        // itself. On Linux the kernel routes traffic to our own bound
        // addresses via `lo` before it ever reaches the TUN, so this branch
        // never fires there. The check is kept unconditional anyway, both as a
        // platform-independent self-delivery invariant and so the path stays
        // exercised by the Linux-only CI unit tests.
        if packet[24..40] == *our_addr.as_bytes() {
            trace!(name = %name, "Hairpinning self-addressed packet back to TUN (loopback)");
            // Finish the checksum macOS leaves offloaded on self-traffic, else the
            // local stack drops every non-SYN segment. See recalculate_l4_checksum.
            recalculate_l4_checksum(packet);
            if tun_tx.send(packet.to_vec()).is_err() {
                return false; // Channel closed, shutdown
            }
            return true;
        }

        // Per-destination clamp: if discovery has learned a smaller path
        // MTU for this destination, tighten the ceiling for this flow.
        let effective_max_mss = per_flow_max_mss(path_mtu_lookup, &packet[24..40], max_mss);
        if clamp_tcp_mss(packet, effective_max_mss) {
            trace!(name = %name, max_mss = effective_max_mss, "Clamped TCP MSS in SYN packet");
        }
        if outbound_tx.blocking_send(packet.to_vec()).is_err() {
            return false; // Channel closed, shutdown
        }
    } else {
        // Non-FIPS destination: send ICMPv6 Destination Unreachable
        if should_send_icmp_error(packet)
            && let Some(response) =
                build_dest_unreachable(packet, DestUnreachableCode::NoRoute, our_addr.to_ipv6())
        {
            trace!(name = %name, len = response.len(), "Sending ICMPv6 Destination Unreachable (non-FIPS destination)");
            if tun_tx.send(response).is_err() {
                return false;
            }
        }
    }
    true
}

#[cfg(unix)]
impl std::fmt::Debug for TunDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunDevice")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .field("address", &self.address)
            .finish()
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
#[cfg(unix)]
pub async fn shutdown_tun_interface(name: &str) -> Result<(), TunError> {
    debug!("Shutting down TUN interface {}", name);
    platform::delete_interface(name).await?;
    debug!("TUN interface {} stopped", name);
    Ok(())
}

// ============================================================================
// Windows TUN implementation (wintun)
// ============================================================================

#[cfg(windows)]
mod windows_tun {
    use super::*;
    use crate::TunConfig;
    use std::sync::Arc;

    /// The Windows adapter name visible in network settings and used in netsh commands.
    pub(crate) const ADAPTER_NAME: &str = "FIPS";

    /// Wintun ring buffer capacity in bytes. Must be a power of 2 between
    /// 0x20000 (128 KiB) and 0x4000000 (64 MiB). 2 MiB balances memory
    /// usage against burst tolerance.
    const WINTUN_RING_CAPACITY: u32 = 0x200000; // 2 MiB

    /// FIPS TUN device wrapper (Windows/wintun).
    ///
    /// Uses the wintun driver for userspace packet I/O on Windows. The wintun
    /// DLL must be present in the executable's directory or system PATH.
    /// Adapter creation requires Administrator privileges.
    ///
    /// Unlike the Linux TUN which uses a file descriptor, wintun uses a
    /// session-based API with ring buffers for packet exchange.
    pub struct TunDevice {
        session: Arc<wintun::Session>,
        _adapter: Arc<wintun::Adapter>,
        name: String,
        mtu: u16,
        address: FipsAddress,
    }

    impl TunDevice {
        /// Create a wintun TUN adapter and configure it with an IPv6 address.
        ///
        /// Loads the wintun DLL, creates (or reopens) a named adapter, starts
        /// a session with a 2 MiB ring buffer, and configures the interface
        /// via netsh. Requires Administrator privileges.
        pub async fn create(config: &TunConfig, address: FipsAddress) -> Result<Self, TunError> {
            let name = config.name();
            let mtu = config.mtu();

            // Load the wintun DLL
            let wintun = unsafe { wintun::load() }.map_err(|e| {
                TunError::Create(
                    format!(
                        "Failed to load wintun.dll: {}. Download from https://www.wintun.net/",
                        e
                    )
                    .into(),
                )
            })?;

            // Create or reopen the adapter.
            // First arg: adapter name visible in Windows network settings.
            // Second arg: tunnel type (internal identifier for wintun).
            let adapter = match wintun::Adapter::create(&wintun, ADAPTER_NAME, name, None) {
                Ok(a) => a,
                Err(e) => {
                    return Err(TunError::Create(
                        format!(
                            "Failed to create wintun adapter '{}': {}. Run as Administrator.",
                            name, e
                        )
                        .into(),
                    ));
                }
            };

            // Start a session with the configured ring buffer capacity
            let session = adapter.start_session(WINTUN_RING_CAPACITY).map_err(|e| {
                TunError::Create(format!("Failed to start wintun session: {}", e).into())
            })?;

            let session = Arc::new(session);

            // Configure the IPv6 address and route via netsh.
            // Use the adapter name (ADAPTER_NAME) not the tunnel type name.
            let ipv6_addr = address.to_ipv6();
            configure_windows_interface(ADAPTER_NAME, ipv6_addr, mtu).await?;

            Ok(Self {
                session,
                _adapter: adapter,
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

        /// Read a packet from the TUN device.
        ///
        /// Blocks until a packet is available from the wintun session.
        /// Returns the number of bytes copied into `buf`.
        pub fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
            match self.session.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.bytes();
                    let len = bytes.len().min(buf.len());
                    buf[..len].copy_from_slice(&bytes[..len]);
                    Ok(len)
                }
                Err(e) => Err(TunError::Configure(format!("read failed: {}", e))),
            }
        }

        /// Shutdown the TUN device by removing the fd00::/8 route.
        ///
        /// The wintun adapter and session are cleaned up when dropped.
        pub async fn shutdown(&self) -> Result<(), TunError> {
            debug!(name = %self.name, "Shutting down TUN device");
            let _ = tokio::process::Command::new("netsh")
                .args([
                    "interface",
                    "ipv6",
                    "delete",
                    "route",
                    "fd00::/8",
                    &format!("interface={}", ADAPTER_NAME),
                ])
                .output()
                .await;
            Ok(())
        }

        /// Create a TunWriter for this device.
        ///
        /// Clones the wintun session `Arc` so the writer can allocate and send
        /// packets independently. Returns the writer and a channel sender for
        /// submitting packets to be written.
        ///
        /// `max_mss` is the global TCP MSS ceiling. `path_mtu_lookup` is a
        /// read-only handle to per-destination path MTU learned via
        /// discovery.
        pub fn create_writer(
            &self,
            max_mss: u16,
            path_mtu_lookup: PathMtuLookup,
        ) -> Result<(TunWriter, TunTx), TunError> {
            let (tx, rx) = mpsc::channel();
            Ok((
                TunWriter {
                    session: self.session.clone(),
                    rx,
                    name: self.name.clone(),
                    max_mss,
                    path_mtu_lookup,
                },
                tx,
            ))
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

    /// Writer thread for TUN device (Windows).
    ///
    /// Services a queue of outbound packets and writes them to the wintun
    /// session. Uses `allocate_send_packet()` / `send_packet()` instead of
    /// file I/O.
    ///
    /// Also performs TCP MSS clamping on inbound SYN-ACK packets.
    pub struct TunWriter {
        session: Arc<wintun::Session>,
        rx: mpsc::Receiver<Vec<u8>>,
        name: String,
        max_mss: u16,
        path_mtu_lookup: PathMtuLookup,
    }

    impl TunWriter {
        /// Run the writer loop.
        ///
        /// Blocks forever, reading packets from the channel and writing them
        /// to the wintun session. Returns when the channel is closed.
        pub fn run(self) {
            use super::per_flow_max_mss;
            use crate::upper::tcp_mss::clamp_tcp_mss;

            debug!(name = %self.name, max_mss = self.max_mss, "TUN writer starting");

            for mut packet in self.rx {
                // Per-destination clamp (peer source IPv6 = bytes 8..24)
                let effective_max_mss = if packet.len() >= 24 {
                    per_flow_max_mss(&self.path_mtu_lookup, &packet[8..24], self.max_mss)
                } else {
                    self.max_mss
                };
                // Clamp TCP MSS on inbound SYN-ACK packets
                if clamp_tcp_mss(&mut packet, effective_max_mss) {
                    trace!(
                        name = %self.name,
                        max_mss = effective_max_mss,
                        "Clamped TCP MSS in inbound SYN-ACK packet"
                    );
                }

                let pkt_len = match u16::try_from(packet.len()) {
                    Ok(len) => len,
                    Err(_) => {
                        warn!(name = %self.name, len = packet.len(), "Dropping oversized packet for TUN");
                        continue;
                    }
                };
                match self.session.allocate_send_packet(pkt_len) {
                    Ok(mut send_packet) => {
                        send_packet.bytes_mut().copy_from_slice(&packet);
                        self.session.send_packet(send_packet);
                        trace!(name = %self.name, len = packet.len(), "TUN packet written");
                    }
                    Err(e) => {
                        error!(name = %self.name, error = %e, "TUN write error (allocate)");
                    }
                }
            }
        }
    }

    /// TUN packet reader loop (Windows).
    ///
    /// Reads IPv6 packets from the wintun session. Packets destined for FIPS
    /// addresses (fd::/8) are forwarded to the Node via the outbound channel
    /// for session encapsulation and routing. Non-FIPS packets receive ICMPv6
    /// Destination Unreachable responses.
    ///
    /// Also performs TCP MSS clamping on SYN packets to prevent oversized segments.
    ///
    /// This is designed to run in a dedicated thread since wintun reads are blocking.
    /// The loop exits when the session is closed or an unrecoverable error occurs.
    pub fn run_tun_reader(
        mut device: TunDevice,
        mtu: u16,
        our_addr: FipsAddress,
        tun_tx: TunTx,
        outbound_tx: TunOutboundTx,
        transport_mtu: u16,
        path_mtu_lookup: PathMtuLookup,
    ) {
        let (name, mut buf, max_mss) = super::tun_reader_setup(device.name(), mtu, transport_mtu);

        loop {
            match device.read_packet(&mut buf) {
                Ok(n) if n > 0 => {
                    if !super::handle_tun_packet(
                        &mut buf[..n],
                        max_mss,
                        &name,
                        our_addr,
                        &tun_tx,
                        &outbound_tx,
                        &path_mtu_lookup,
                    ) {
                        break;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    let err_str = format!("{}", e);
                    if !err_str.contains("Bad address") {
                        error!(name = %name, error = %e, "TUN read error");
                    }
                    break;
                }
            }
        }
    }

    /// Shutdown and delete a TUN interface by name (Windows).
    ///
    /// Removes the fd00::/8 route via netsh. The wintun adapter itself
    /// is cleaned up when the `Adapter` handle is dropped.
    pub async fn shutdown_tun_interface(name: &str) -> Result<(), TunError> {
        debug!("Shutting down TUN interface {}", name);
        let _ = tokio::process::Command::new("netsh")
            .args([
                "interface",
                "ipv6",
                "delete",
                "route",
                "fd00::/8",
                &format!("interface={}", ADAPTER_NAME),
            ])
            .output()
            .await;
        let _ = name; // name is the tunnel type, not the adapter name
        debug!("TUN interface {} stopped", name);
        Ok(())
    }

    /// Configure the Windows network interface with IPv6 address, MTU, and route.
    ///
    /// Uses `netsh` commands to configure the wintun adapter. A brief delay
    /// is inserted before configuration to allow Windows to fully register
    /// the adapter in its network stack.
    ///
    /// `adapter_name` must be the Windows adapter name (e.g. "FIPS"), not the
    /// wintun tunnel type name.
    async fn configure_windows_interface(
        adapter_name: &str,
        addr: Ipv6Addr,
        mtu: u16,
    ) -> Result<(), TunError> {
        // Brief delay to let Windows fully register the adapter
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Set IPv6 address
        let output = tokio::process::Command::new("netsh")
            .args([
                "interface",
                "ipv6",
                "add",
                "address",
                adapter_name,
                &format!("{}/128", addr),
            ])
            .output()
            .await
            .map_err(|e| TunError::Configure(format!("netsh add address failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stderr.contains("already") && !stdout.contains("already") {
                warn!(
                    "netsh add address failed: stdout={} stderr={}",
                    stdout.trim(),
                    stderr.trim()
                );
            }
        }

        // Set MTU
        let output = tokio::process::Command::new("netsh")
            .args([
                "interface",
                "ipv6",
                "set",
                "subinterface",
                adapter_name,
                &format!("mtu={}", mtu),
            ])
            .output()
            .await
            .map_err(|e| TunError::Configure(format!("netsh set mtu failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            warn!(
                "netsh set mtu failed: stdout={} stderr={}",
                stdout.trim(),
                stderr.trim()
            );
        }

        // Add route for fd00::/8 (FIPS address space) via this adapter
        let output = tokio::process::Command::new("netsh")
            .args([
                "interface",
                "ipv6",
                "add",
                "route",
                "fd00::/8",
                adapter_name,
            ])
            .output()
            .await
            .map_err(|e| TunError::Configure(format!("netsh add route failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stderr.contains("already") && !stdout.contains("already") {
                warn!(
                    "netsh add route failed: stdout={} stderr={}",
                    stdout.trim(),
                    stderr.trim()
                );
            }
        }

        Ok(())
    }
}

// Re-export Windows TUN types at module level
#[cfg(windows)]
pub use windows_tun::{TunDevice, TunWriter, run_tun_reader, shutdown_tun_interface};

#[cfg(target_os = "linux")]
mod platform {
    use super::TunError;
    use futures::TryStreamExt;
    use rtnetlink::{Handle, LinkUnspec, RouteMessageBuilder, new_connection};
    use std::net::Ipv6Addr;
    use tracing::debug;

    /// Check if IPv6 is disabled system-wide.
    pub fn is_ipv6_disabled() -> bool {
        std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
            .map(|s| s.trim() == "1")
            .unwrap_or(false)
    }

    /// Check if a network interface already exists.
    pub async fn interface_exists(name: &str) -> bool {
        let Ok((connection, handle, _)) = new_connection() else {
            return false;
        };
        tokio::spawn(connection);

        get_interface_index(&handle, name).await.is_ok()
    }

    /// Delete a network interface by name.
    pub async fn delete_interface(name: &str) -> Result<(), TunError> {
        let (connection, handle, _) = new_connection()
            .map_err(|e| TunError::Configure(format!("netlink connection failed: {}", e)))?;
        tokio::spawn(connection);

        let index = get_interface_index(&handle, name).await?;
        handle.link().del(index).execute().await?;
        Ok(())
    }

    /// Configure a network interface with an IPv6 address via netlink.
    pub async fn configure_interface(name: &str, addr: Ipv6Addr, mtu: u16) -> Result<(), TunError> {
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
            .change(LinkUnspec::new_with_index(index).mtu(mtu as u32).build())
            .execute()
            .await?;

        // Bring interface up
        handle
            .link()
            .change(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await?;

        // Add route for fd00::/8 (FIPS address space) via this interface
        let fd_prefix: Ipv6Addr = "fd00::".parse().unwrap();
        let route = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(fd_prefix, 8)
            .output_interface(index)
            .build();
        handle
            .route()
            .add(route)
            .execute()
            .await
            .map_err(|e| TunError::Configure(format!("failed to add fd00::/8 route: {}", e)))?;

        // Add ip6 rule to ensure fd00::/8 uses the main table, preventing other
        // routing software (e.g. Tailscale) from intercepting FIPS traffic via
        // catch-all rules in auxiliary routing tables.
        let mut rule_req = handle
            .rule()
            .add()
            .v6()
            .destination_prefix(fd_prefix, 8)
            .table_id(254)
            .priority(5265);
        rule_req.message_mut().header.action = 1.into(); // FR_ACT_TO_TBL
        if let Err(e) = rule_req.execute().await {
            debug!("ip6 rule for fd00::/8 not added (may already exist): {e}");
        }

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
}

#[cfg(target_os = "macos")]
mod platform {
    use super::TunError;
    use std::net::Ipv6Addr;
    use tokio::process::Command;

    /// Check if IPv6 is disabled system-wide.
    pub fn is_ipv6_disabled() -> bool {
        // macOS: check via sysctl; if the key doesn't exist, IPv6 is enabled
        std::process::Command::new("sysctl")
            .args(["-n", "net.inet6.ip6.disabled"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "1")
            .unwrap_or(false)
    }

    /// Check if a network interface already exists.
    pub async fn interface_exists(name: &str) -> bool {
        Command::new("ifconfig")
            .arg(name)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Shut down a network interface by name.
    ///
    /// On macOS, utun devices are automatically destroyed when the file
    /// descriptor is closed. Bringing the interface down causes any
    /// blocking reads to return an error, which unblocks the reader thread.
    pub async fn delete_interface(name: &str) -> Result<(), TunError> {
        run_cmd("ifconfig", &[name, "down"]).await
    }

    /// Configure a network interface with an IPv6 address using ifconfig/route.
    pub async fn configure_interface(name: &str, addr: Ipv6Addr, mtu: u16) -> Result<(), TunError> {
        // Add IPv6 address with /128 prefix
        run_cmd(
            "ifconfig",
            &[name, "inet6", &addr.to_string(), "prefixlen", "128"],
        )
        .await?;

        // Set MTU
        run_cmd("ifconfig", &[name, "mtu", &mtu.to_string()]).await?;

        // Bring interface up
        run_cmd("ifconfig", &[name, "up"]).await?;

        // Add route for fd00::/8 (FIPS address space) via this interface
        run_cmd(
            "route",
            &[
                "add",
                "-inet6",
                "-prefixlen",
                "8",
                "fd00::",
                "-interface",
                name,
            ],
        )
        .await?;

        Ok(())
    }

    /// Run a command and return an error if it fails.
    async fn run_cmd(program: &str, args: &[&str]) -> Result<(), TunError> {
        let output = Command::new(program)
            .args(args)
            .output()
            .await
            .map_err(|e| TunError::Configure(format!("{} failed: {}", program, e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunError::Configure(format!(
                "{} {} failed: {}",
                program,
                args.join(" "),
                stderr.trim()
            )));
        }
        Ok(())
    }
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

    // ========================================================================
    // per_flow_max_mss — per-destination MSS clamp regression coverage
    // ========================================================================

    fn fips_addr_with_node_byte(b: u8) -> FipsAddress {
        let mut bytes = [0u8; 16];
        bytes[0] = crate::identity::FIPS_ADDRESS_PREFIX;
        bytes[1] = b;
        FipsAddress::from_bytes(bytes).unwrap()
    }

    fn empty_lookup() -> PathMtuLookup {
        Arc::new(RwLock::new(HashMap::new()))
    }

    #[test]
    fn per_flow_empty_lookup_returns_conservative_ceiling() {
        // Cold-flow first-SYN race-window guard: when no per-destination
        // path_mtu has been learned yet, fall back to the IPv6-minimum-
        // derived ceiling (1280 - 77 - 60 = 1143) rather than the local
        // global ceiling. This ensures the first SYN to an unknown
        // destination clamps small enough to traverse any RFC-8200-
        // compliant IPv6 path.
        let lookup = empty_lookup();
        let addr = fips_addr_with_node_byte(0x42);
        assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1360), 1143);
    }

    #[test]
    fn per_flow_empty_lookup_returns_global_when_global_smaller() {
        // When the local global ceiling is already <= the conservative
        // 1143 ceiling (e.g. a daemon configured with UDP-1280 only),
        // the empty-lookup fallback stays at the global rather than
        // expanding upward.
        let lookup = empty_lookup();
        let addr = fips_addr_with_node_byte(0x42);
        assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1100), 1100);
    }

    #[test]
    fn per_flow_clamps_to_path_mtu_when_smaller() {
        // Discovery learned path_mtu=1280 for this destination; global
        // ceiling is 1360. Per-flow clamp should be min(1360, 1280-77-60)
        // = min(1360, 1143) = 1143.
        let lookup = empty_lookup();
        let addr = fips_addr_with_node_byte(0x42);
        lookup.write().unwrap().insert(addr, 1280);
        assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1360), 1143);
    }

    #[test]
    fn per_flow_keeps_global_when_path_mtu_larger() {
        // Discovery learned path_mtu=1452 (> global). Per-flow stays at
        // global 1143 (the smaller of the two).
        let lookup = empty_lookup();
        let addr = fips_addr_with_node_byte(0x42);
        lookup.write().unwrap().insert(addr, 1452);
        // global=1143 (UDP-1280-derived); path_max = 1452-77-60 = 1315.
        assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1143), 1143);
    }

    #[test]
    fn per_flow_learned_value_overrides_conservative_ceiling() {
        // When discovery has learned a per-destination value LARGER than
        // the conservative 1143 ceiling, the learned value (capped by
        // the global ceiling) wins. The conservative ceiling is only the
        // empty-lookup fallback; once an entry exists, the actual
        // learned value governs.
        let lookup = empty_lookup();
        let addr = fips_addr_with_node_byte(0x42);
        lookup.write().unwrap().insert(addr, 1452);
        // global=1360, path_max = 1452-77-60 = 1315; min(1360, 1315) = 1315.
        // 1315 > 1143, so the conservative ceiling did NOT clamp here.
        assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1360), 1315);
    }

    #[test]
    fn per_flow_returns_conservative_ceiling_for_non_fips_addr() {
        // Non-fips IPv6 (e.g. fe80::/10 link-local) takes the empty-
        // lookup path. With global=1360, fall back to 1143.
        let lookup = empty_lookup();
        let mut bytes = [0u8; 16];
        bytes[0] = 0xfe;
        bytes[1] = 0x80;
        assert_eq!(per_flow_max_mss(&lookup, &bytes, 1360), 1143);
    }

    #[test]
    fn per_flow_returns_conservative_ceiling_on_short_addr_slice() {
        let lookup = empty_lookup();
        let bytes = [0u8; 8];
        assert_eq!(per_flow_max_mss(&lookup, &bytes, 1360), 1143);
    }

    #[test]
    fn per_flow_independent_per_destination() {
        // Two different destinations with different path MTUs. Each
        // lookup honors its own value; cross-talk would be a regression.
        let lookup = empty_lookup();
        let a = fips_addr_with_node_byte(0x10);
        let b = fips_addr_with_node_byte(0x20);
        lookup.write().unwrap().insert(a, 1280);
        lookup.write().unwrap().insert(b, 1452);
        assert_eq!(per_flow_max_mss(&lookup, a.as_bytes(), 1360), 1143);
        assert_eq!(per_flow_max_mss(&lookup, b.as_bytes(), 1360), 1315);
    }

    // ========================================================================
    // handle_tun_packet — self-addressed loopback hairpin
    //
    // A packet destined for our own mesh address must be delivered back to
    // the local stack via the TUN writer, never pushed into the mesh (there
    // is no session/route to ourselves). On macOS the kernel egresses such
    // self-traffic down the utun into the reader, so the daemon has to loop
    // it back itself.
    // ========================================================================

    /// Build a minimal 40-byte IPv6 packet (no upper-layer payload) addressed
    /// to `dst`, sourced from a distinct fips address.
    fn ipv6_packet_to(dst: &FipsAddress) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // version 6
        pkt[6] = 59; // next header = No Next Header (skips MSS clamp)
        pkt[7] = 64; // hop limit
        pkt[8] = crate::identity::FIPS_ADDRESS_PREFIX; // src in fd::/8
        pkt[24..40].copy_from_slice(dst.as_bytes()); // dst
        pkt
    }

    #[test]
    fn self_addressed_packet_is_hairpinned_to_tun() {
        let our_addr = fips_addr_with_node_byte(0x55);
        let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>();
        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
        let lookup = empty_lookup();
        let mut pkt = ipv6_packet_to(&our_addr);

        assert!(handle_tun_packet(
            &mut pkt,
            1360,
            "test0",
            our_addr,
            &tun_tx,
            &outbound_tx,
            &lookup,
        ));

        // Delivered locally via the TUN writer...
        let looped = tun_rx
            .try_recv()
            .expect("self-addressed packet should be hairpinned to the TUN");
        assert_eq!(&looped[24..40], our_addr.as_bytes());
        // ...and never handed to the mesh.
        assert!(
            outbound_rx.try_recv().is_err(),
            "self-addressed packet must not be pushed into the mesh"
        );
    }

    #[test]
    fn other_fips_packet_goes_to_mesh() {
        let our_addr = fips_addr_with_node_byte(0x55);
        let peer = fips_addr_with_node_byte(0x66);
        let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>();
        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
        let lookup = empty_lookup();
        let mut pkt = ipv6_packet_to(&peer);

        assert!(handle_tun_packet(
            &mut pkt,
            1360,
            "test0",
            our_addr,
            &tun_tx,
            &outbound_tx,
            &lookup,
        ));

        // A non-self fips destination is routed into the mesh, not looped back.
        assert!(
            outbound_rx.try_recv().is_ok(),
            "non-self fips destination should be sent to the mesh"
        );
        assert!(
            tun_rx.try_recv().is_err(),
            "non-self fips destination must not be hairpinned"
        );
    }

    // ========================================================================
    // macOS utun packet-info header (AF_INET6 4-byte big-endian prefix)
    //
    // These tests are pure-data byte-buffer manipulation and require no
    // privilege, no actual TUN device, no system calls. They pin the wire
    // format that `TunWriter::run` emits ahead of every IPv6 frame on the
    // dup'd utun fd, and the inverse parse used for round-trip checking.
    // ========================================================================

    #[cfg(target_os = "macos")]
    mod macos_utun_header {
        use super::super::{UTUN_AF_INET6, parse_utun_af_prefix, utun_af_inet6_header};

        #[test]
        fn af_inet6_constant_matches_darwin() {
            // Darwin's <sys/socket.h> defines AF_INET6 = 30. If this ever
            // diverges, every utun write FIPS issues will be misclassified
            // by the kernel and dropped.
            assert_eq!(UTUN_AF_INET6, 30);
        }

        #[test]
        fn encode_produces_big_endian_af_inet6() {
            // The kernel reads the 4-byte prefix as a big-endian u32.
            // 30 == 0x0000001e, so the wire bytes are [0, 0, 0, 0x1e].
            let header = utun_af_inet6_header();
            assert_eq!(header, [0x00, 0x00, 0x00, 0x1e]);
        }

        #[test]
        fn encode_round_trips_through_parse() {
            let header = utun_af_inet6_header();
            let parsed = parse_utun_af_prefix(&header).expect("4 bytes is enough");
            assert_eq!(parsed, UTUN_AF_INET6);
        }

        #[test]
        fn parse_rejects_short_buffer() {
            // Anything shorter than the 4-byte header is ill-formed.
            assert_eq!(parse_utun_af_prefix(&[]), None);
            assert_eq!(parse_utun_af_prefix(&[0x00]), None);
            assert_eq!(parse_utun_af_prefix(&[0x00, 0x00]), None);
            assert_eq!(parse_utun_af_prefix(&[0x00, 0x00, 0x00]), None);
        }

        #[test]
        fn parse_accepts_minimum_header_with_trailing_payload() {
            // A real utun read returns header + IP packet concatenated.
            // The parser only consumes the first 4 bytes.
            let mut frame = utun_af_inet6_header().to_vec();
            frame.extend_from_slice(&[0x60; 40]); // dummy IPv6 header
            let parsed = parse_utun_af_prefix(&frame).expect("4 bytes is enough");
            assert_eq!(parsed, UTUN_AF_INET6);
        }

        #[test]
        fn parse_garbage_bytes_returns_garbage_value_not_panic() {
            // A well-formed 4-byte buffer whose value is not AF_INET6
            // should parse successfully (returning the raw u32) without
            // panicking. Discriminating "expected" vs "unexpected" AF
            // values is the caller's responsibility.
            let buf = [0xde, 0xad, 0xbe, 0xef];
            let parsed = parse_utun_af_prefix(&buf).expect("4 bytes is enough");
            assert_eq!(parsed, 0xdeadbeef);
            assert_ne!(parsed, UTUN_AF_INET6);
        }
    }
}
