//! FIPS TUN Interface
//!
//! Manages the TUN device for sending and receiving IPv6 packets.
//! The TUN interface presents mesh IPv6 addresses to the local system,
//! allowing standard socket applications to communicate over the mesh.
//!
//! Platform-specific implementations:
//! - Linux: Uses the `tun` crate with `rtnetlink` for interface configuration
//! - macOS/FreeBSD: Uses the `tun` crate, with interface ioctls and the
//!   routing socket for interface configuration
//! - Windows: Uses the `wintun` crate for TUN device support, with IP Helper
//!   for interface configuration

#[cfg(windows)]
use crate::Ipv6Address;
#[cfg(unix)]
use crate::{Ipv6Address, TunConfig};
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Read;
#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
#[cfg(unix)]
use std::io::Write;
use std::net::Ipv6Addr;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::{Arc, mpsc};
use thiserror::Error;
#[cfg(unix)]
use tracing::error;
use tracing::{debug, trace};
#[cfg(windows)]
use tracing::{error, warn};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
use tun::Layer;

use super::core::PathMtuReplica;

/// The IPv6 minimum link MTU (RFC 8200): every compliant path accepts a packet
/// this large, so an MSS derived from it fits anywhere.
///
/// Three uses, and they must not disagree: the cold-flow fallback in
/// [`per_flow_max_mss`], and the two seeds of the node-wide limit before any
/// transport has bound, the adapter's (`MeshState::new`) and the node's record
/// of what it has published (`NodeMtuFeed::new`). It is also the value
/// `Node::transport_mtu()` falls back to when nothing is bound.
pub const IPV6_MIN_MTU: u16 = 1280;

/// The TCP MSS ceiling the IPv6 adapter derives from the node-wide payload
/// limit, shared live with the TUN reader and writer threads.
///
/// Shared rather than copied because the limit moves at runtime. The node
/// publishes it from `Node::transport_mtu()`, the minimum across *bound*
/// transports, and a transport can bind minutes after start or unbind
/// mid-operation: a narrow interface appearing must tighten the clamp, and
/// its departure must release it. The adapter stores the ceiling of each
/// limit the node pushes over the link here (`MeshState` in `core.rs`), so
/// the threads clamp by the limit last published rather than one captured
/// at spawn.
///
/// A relaxed load per packet, beside the `PathMtuReplica` read that already
/// happens on the same packet — strictly the cheaper of the two. Ordering is
/// irrelevant: this is a clamp, and a packet that reads the previous value
/// during the store is clamped by the ceiling that was correct a microsecond
/// earlier. The per-flow ceiling has always had that property.
pub type MssCeiling = Arc<std::sync::atomic::AtomicU16>;

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
/// The node reports each learned path as a payload limit; the shim turns it
/// into an IPv6 MTU, and the 40-byte IPv6 and 20-byte TCP headers come off
/// that (see [`tcp_mss`](super::mtu::tcp_mss)).
pub(crate) fn per_flow_max_mss(
    lookup: &PathMtuReplica,
    addr_bytes: &[u8],
    global_max_mss: u16,
) -> u16 {
    use super::mtu::{mss_ceiling, tcp_mss};

    // RFC 8200 IPv6-minimum MTU (1280) → effective FIPS-encapsulated
    // payload (1203) → TCP segment after IPv6+TCP headers (1143).
    // Used as the conservative ceiling for empty-lookup destinations.
    let conservative_max_mss = mss_ceiling(IPV6_MIN_MTU);
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
    let Ok(fips_addr) = Ipv6Address::from_slice(addr_bytes) else {
        trace!(
            global_max_mss,
            empty_lookup_ceiling,
            "per_flow_max_mss: Ipv6Address::from_slice rejected (non-fd::/8 prefix), fall back to conservative ceiling"
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
    let Some(payload_limit) = map.get(&fips_addr).copied() else {
        trace!(
            fips_addr = %fips_addr,
            global_max_mss,
            empty_lookup_ceiling,
            map_len = map.len(),
            "per_flow_max_mss: no path_mtu_lookup entry for destination, fall back to conservative ceiling"
        );
        return empty_lookup_ceiling;
    };
    let path_max_mss = tcp_mss(payload_limit);
    // The actionable floor deliberately does not apply here. Every value a
    // remote party supplies is refused before it can reach this map, at the
    // path MTU state machine, the reactive `MtuExceeded` write and the
    // discovery response, so a small stored value is one the node derived
    // from its own outgoing link: a configured transport MTU, or the MTU a
    // BLE connection negotiated, which on that transport is routinely well
    // under the floor. Such a value is exact rather than suspect, and the
    // tight clamp it yields is the reason it is stored: discarding it would
    // advertise the conservative ceiling on a link that cannot carry it, and
    // a direct link has no forwarder to answer with `MtuExceeded`, so the
    // flow would stall with no feedback.
    //
    // What no provenance rescues is the arithmetic degenerating. At a stored
    // MTU of 137 or less (a payload limit of 27 or less) not one payload byte fits alongside the IPv6 and TCP
    // headers, and `clamp_tcp_mss` refuses a ceiling of zero, which would
    // leave the SYN carrying the kernel-natural MSS instead. Fall back to the
    // conservative ceiling there; any positive result is by construction the
    // largest segment the stored MTU admits.
    //
    // `trace!`, not `warn!`, because this runs on every packet rather than
    // only on SYNs: one degenerate stored value would otherwise emit a WARN
    // per packet indefinitely and bury every other warning on the node. The
    // link promotion path warns once instead.
    if path_max_mss == 0 {
        trace!(
            fips_addr = %fips_addr,
            payload_limit,
            empty_lookup_ceiling,
            "per_flow_max_mss: stored path_mtu leaves no room for a TCP payload byte, using conservative ceiling"
        );
        return empty_lookup_ceiling;
    }
    let result = std::cmp::min(global_max_mss, path_max_mss);
    trace!(
        fips_addr = %fips_addr,
        payload_limit,
        path_max_mss,
        global_max_mss,
        result,
        "per_flow_max_mss: per-destination clamp applied"
    );
    result
}

/// Channel sender for packets to be written to TUN.
pub type TunTx = mpsc::Sender<Vec<u8>>;

/// Channel sender of the packets an embedder that owns the TUN hands the
/// node.
pub type TunOutboundTx = tokio::sync::mpsc::Sender<Vec<u8>>;
/// Channel receiver of those packets (consumed by Node's RX loop).
pub type TunOutboundRx = tokio::sync::mpsc::Receiver<Vec<u8>>;

/// What the TUN reader needs to run the host half for each packet itself:
/// the adapter's state, the Packet Too Big limiter it shares, and the
/// link's channel of datagrams to the node.
pub(crate) struct HostPath {
    /// The adapter's state: the node-wide IPv6 MTU and the key map.
    pub(crate) state: super::core::MeshState,
    /// The Packet Too Big limiter.
    pub(crate) limiter: Arc<std::sync::Mutex<super::icmp_rate_limit::IcmpRateLimiter>>,
    /// Datagrams to the node.
    pub(crate) datagrams: tokio::sync::mpsc::Sender<super::link::Datagram>,
}

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
    address: Ipv6Address,
}

#[cfg(unix)]
impl TunDevice {
    /// Create or open a TUN device.
    ///
    /// On Linux the device is named `tun.name`. When an interface of that
    /// name already exists: a persistent TUN that no process holds is
    /// reopened and reconfigured, first removing any `fd00::/8` /128 address
    /// and `fd00::/8` route an earlier node left on it by exiting without
    /// stopping; a TUN another process holds is an error; and any other
    /// kind of interface is refused and left untouched. Nothing is deleted
    /// before create. On macOS and FreeBSD the kernel names the device, and
    /// `tun.name` is not used to find an existing one.
    ///
    /// This requires CAP_NET_ADMIN capability (run with sudo or setcap).
    pub async fn create(config: &TunConfig, address: Ipv6Address) -> Result<Self, TunError> {
        // Check if IPv6 is enabled
        if platform::is_ipv6_disabled() {
            return Err(TunError::Ipv6Disabled);
        }

        #[cfg(target_os = "linux")]
        let name = config.name();
        let mtu = config.mtu();

        // An existing interface of this name that is not a TUN belongs to
        // something else: refuse it rather than take it over.
        #[cfg(target_os = "linux")]
        platform::refuse_foreign_link(name).await?;

        // Create the TUN device. `mut` is only exercised on linux/macos, where
        // the name/layer/mtu are set below; other unix targets (android) pass
        // the default config through unchanged.
        #[cfg_attr(
            not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")),
            allow(unused_mut)
        )]
        let mut tun_config = tun::Configuration::default();

        #[cfg(target_os = "linux")]
        #[allow(deprecated)]
        tun_config.name(name).layer(Layer::L3).mtu(mtu);

        // On macOS and FreeBSD the kernel assigns the device name (utun0...,
        // tun0...), so the name is not set here and is read back after
        // creation.
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        {
            #[allow(deprecated)]
            tun_config.layer(Layer::L3).mtu(mtu);
        }

        let device = match tun::create(&tun_config) {
            // TUNSETIFF on a TUN another process holds.
            #[cfg(target_os = "linux")]
            Err(tun::Error::Io(e)) if e.raw_os_error() == Some(libc::EBUSY) => {
                return Err(TunError::Configure(format!(
                    "TUN interface {name} is held by another process"
                )));
            }
            other => other?,
        };

        // FreeBSD: enable TUNSIFHEAD. Without it, tunoutput() rejects every
        // non-IPv4 packet with EAFNOSUPPORT, so nothing IPv6 can be sent
        // through the interface. With it, every frame on the fd carries a
        // 4-byte network-order address-family prefix (like macOS utun),
        // which the reader and writer handle.
        #[cfg(target_os = "freebsd")]
        {
            const TUNSIFHEAD: libc::c_ulong = 0x8004_7460; // _IOW('t', 96, int)
            let enable: libc::c_int = 1;
            if unsafe { libc::ioctl(device.as_raw_fd(), TUNSIFHEAD, &enable) } != 0 {
                return Err(TunError::Configure(format!(
                    "TUNSIFHEAD ioctl failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        // Read the actual device name (on macOS and FreeBSD this is the
        // kernel-assigned utunN / tunN name)
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

    /// Get the IPv6 address assigned to this device.
    pub fn address(&self) -> &Ipv6Address {
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
    /// packet information header, and on FreeBSD (TUNSIFHEAD) the
    /// equivalent 4-byte address-family prefix is stripped here, so this
    /// returns a raw IP packet on all platforms. `Ok(0)` means the frame
    /// carried no payload; callers should skip it.
    ///
    /// The raw `io::Error` is returned so callers can inspect `ErrorKind`
    /// (e.g. `WouldBlock`) or `raw_os_error()` without string matching.
    pub fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let n = self.device.read(buf)?;
        // FreeBSD tun in TUNSIFHEAD mode prefixes every frame with its
        // address family. Strip it here so callers see the same raw-IP
        // contract as on Linux and macOS. Non-IPv6 families pass through
        // stripped — matching macOS, where the tun crate does the same —
        // and are dropped by the IPv6 version check in handle_tun_packet.
        #[cfg(target_os = "freebsd")]
        let n = match parse_utun_af_prefix(&buf[..n]) {
            Some(_) if n > 4 => {
                buf.copy_within(4..n, 0);
                n - 4
            }
            // Header-only or truncated frame: no payload.
            _ => 0,
        };
        Ok(n)
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
    /// `max_mss` is the adapter's TCP MSS ceiling, derived from the
    /// node-wide payload limit and shared live so a transport that binds or
    /// unbinds after start moves it (see [`MssCeiling`]). `path_mtu_lookup`
    /// is the adapter's copy of the per-peer payload limits, filled from the
    /// node's messages on the link; the writer reads both on each inbound
    /// SYN to compute a per-flow ceiling that honors learned narrow paths
    /// through the mesh.
    pub fn create_writer(
        &self,
        max_mss: MssCeiling,
        path_mtu_lookup: PathMtuReplica,
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

/// Address-family value for IPv6 in the 4-byte packet-info header used
/// by macOS `utun` and FreeBSD `tun` (TUNSIFHEAD) devices: the target's
/// `AF_INET6` — 30 on Darwin, 28 on FreeBSD.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const UTUN_AF_INET6: u32 = libc::AF_INET6 as u32;

/// Build the 4-byte big-endian packet-info header for an IPv6 frame.
///
/// macOS utun and FreeBSD tun (TUNSIFHEAD) devices require a 4-byte
/// address-family prefix on every frame: a single big-endian `u32`
/// carrying the protocol family. For IPv6 traffic (the only family FIPS
/// sends) this is the target's `AF_INET6`.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
#[inline]
fn utun_af_inet6_header() -> [u8; 4] {
    UTUN_AF_INET6.to_be_bytes()
}

/// Parse the 4-byte big-endian packet-info header.
///
/// Returns the address-family value, or `None` if the buffer is shorter
/// than the 4-byte header. On FreeBSD [`TunDevice::read_packet`] strips
/// the prefix with this; on macOS the `tun` crate's `Read` impl strips
/// it before we see the frame, so there the helper is exercised only by
/// the round-trip tests below.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
#[cfg_attr(target_os = "macos", allow(dead_code))]
#[inline]
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
/// Also performs TCP MSS clamping on inbound SYN-flagged packets (SYN and SYN-ACK).
#[cfg(unix)]
pub struct TunWriter {
    file: File,
    rx: mpsc::Receiver<Vec<u8>>,
    name: String,
    max_mss: MssCeiling,
    path_mtu_lookup: PathMtuReplica,
}

#[cfg(unix)]
impl TunWriter {
    /// Run the writer loop.
    ///
    /// Blocks forever, reading packets from the channel and writing them
    /// to the TUN device. Returns when the channel is closed (all senders dropped).
    #[cfg_attr(any(target_os = "macos", target_os = "freebsd"), allow(unused_mut))]
    pub fn run(mut self) {
        use super::tcp_mss::clamp_tcp_mss;

        debug!(
            name = %self.name,
            max_mss = self.max_mss.load(std::sync::atomic::Ordering::Relaxed),
            "TUN writer starting"
        );

        for mut packet in self.rx {
            // Read per packet, not once: a transport binding or unbinding
            // moves the node's egress floor at runtime. See `MssCeiling`.
            let global_max_mss = self.max_mss.load(std::sync::atomic::Ordering::Relaxed);
            // Per-destination clamp: peer IPv6 source address (bytes 8..24)
            // identifies the flow's remote end. If discovery has learned a
            // smaller path MTU for that peer, tighten the ceiling.
            let effective_max_mss = if packet.len() >= 24 {
                per_flow_max_mss(&self.path_mtu_lookup, &packet[8..24], global_max_mss)
            } else {
                global_max_mss
            };
            // Clamp TCP MSS on inbound SYN-flagged packets
            if clamp_tcp_mss(&mut packet, effective_max_mss) {
                trace!(
                    name = %self.name,
                    max_mss = effective_max_mss,
                    "Clamped TCP MSS in inbound SYN packet"
                );
            }

            // On macOS (utun) and FreeBSD (tun with TUNSIFHEAD), the device
            // requires a 4-byte network-order address-family header prepended
            // to each packet. The tun crate handles this for its own
            // Read/Write impl, but we use a dup'd fd directly. We use writev
            // to avoid allocating a buffer on every packet.
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
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
            #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
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
/// Reads IPv6 packets from the TUN device. Packets destined for mesh addresses
/// (fd::/8) are forwarded to the Node via the outbound channel for session
/// encapsulation and routing. Non-FIPS packets receive ICMPv6 Destination
/// Unreachable responses.
///
/// Also performs TCP MSS clamping on SYN packets to prevent oversized segments.
///
/// This is designed to run in a dedicated thread since TUN reads are blocking.
/// The loop exits when the TUN interface is deleted (EFAULT) or an unrecoverable
/// error occurs.
#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
#[cfg(unix)]
pub(crate) fn run_tun_reader(
    mut device: TunDevice,
    mtu: u16,
    our_addr: Ipv6Address,
    tun_tx: TunTx,
    host: HostPath,
    max_mss: MssCeiling,
    path_mtu_lookup: PathMtuReplica,
) {
    let (name, mut buf) = tun_reader_setup(device.name(), mtu, &max_mss);

    loop {
        match device.read_packet(&mut buf) {
            Ok(n) if n > 0 => {
                if !handle_tun_packet(
                    &mut buf[..n],
                    max_mss.load(std::sync::atomic::Ordering::Relaxed),
                    &name,
                    our_addr,
                    &tun_tx,
                    &host,
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
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
struct ShutdownFd(std::os::unix::io::RawFd);

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
impl Drop for ShutdownFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// TUN packet reader loop (macOS / FreeBSD).
///
/// Uses `select()` to multiplex between the TUN fd and a shutdown pipe,
/// avoiding the need to close the TUN fd externally (which would cause a
/// double-close when `TunDevice` drops). Both platforms need the pipe
/// because downing the interface does not reliably unblock a thread
/// parked in a blocking TUN read on either of them.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_tun_reader(
    mut device: TunDevice,
    mtu: u16,
    our_addr: Ipv6Address,
    tun_tx: TunTx,
    host: HostPath,
    max_mss: MssCeiling,
    path_mtu_lookup: PathMtuReplica,
    shutdown_fd: std::os::unix::io::RawFd,
) {
    let _shutdown_fd = ShutdownFd(shutdown_fd);
    let tun_fd = device.device().as_raw_fd();
    let (name, mut buf) = tun_reader_setup(device.name(), mtu, &max_mss);

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
                        max_mss.load(std::sync::atomic::Ordering::Relaxed),
                        &name,
                        our_addr,
                        &tun_tx,
                        &host,
                        &path_mtu_lookup,
                    ) {
                        return; // _shutdown_fd closes on drop
                    }
                }
                // No more data, or an empty/skipped frame — either way
                // fall back to select for the next readable event.
                Ok(_) => break,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break; // Done for this select round
                    }
                    // EBADF is expected during shutdown when the fd is
                    // closed; ENXIO when the interface was destroyed out
                    // from under the fd (FreeBSD).
                    if e.raw_os_error() != Some(libc::EBADF)
                        && e.raw_os_error() != Some(libc::ENXIO)
                    {
                        error!(name = %name, error = %e, "TUN read error");
                    }
                    return; // _shutdown_fd closes on drop
                }
            }
        }
    }
    // _shutdown_fd closes on drop
}

/// Common setup for TUN reader: allocates the buffer and names the device.
///
/// The MSS ceiling is deliberately *not* returned. It is read from the shared
/// [`MssCeiling`] on every packet, because a transport binding or unbinding
/// moves it after this function has run; returning it here is what let the
/// reader clamp to a floor derived from the transports that happened to be
/// bound at spawn.
fn tun_reader_setup(device_name: &str, mtu: u16, max_mss: &MssCeiling) -> (String, Vec<u8>) {
    let name = device_name.to_string();
    let buf = vec![0u8; mtu as usize + 100];

    debug!(
        name = %name,
        tun_mtu = mtu,
        max_mss = max_mss.load(std::sync::atomic::Ordering::Relaxed),
        "TUN reader starting"
    );

    (name, buf)
}

/// Process a single TUN packet. Returns `false` if the reader should exit.
fn handle_tun_packet(
    packet: &mut [u8],
    max_mss: u16,
    name: &str,
    our_addr: Ipv6Address,
    tun_tx: &TunTx,
    host: &HostPath,
    path_mtu_lookup: &PathMtuReplica,
) -> bool {
    use super::icmp::{DestUnreachableCode, build_dest_unreachable, should_send_icmp_error};
    use super::tcp_mss::{clamp_tcp_mss, recalculate_l4_checksum};

    log_ipv6_packet(packet);

    // Must be a valid IPv6 packet
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return true;
    }

    // Check if destination is a mesh IPv6 address (fd00::/8 prefix)
    if packet[24] == crate::identity::IPV6_ADDRESS_PREFIX {
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
        let mut icmp =
            super::icmp::IcmpContext::new(Some(tun_tx), our_addr.to_ipv6(), &host.limiter);
        if let Some(datagram) = super::outbound::outbound(packet, &host.state, &mut icmp)
            && host.datagrams.blocking_send(datagram).is_err()
        {
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

    /// The Windows adapter name visible in network settings.
    pub(crate) const ADAPTER_NAME: &str = "FIPS";

    /// The mesh address space routed into the adapter: `fd00::/8`.
    const MESH_PREFIX: (Ipv6Addr, u8) = (Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 8);

    /// How long a new adapter may take to appear in the IPv6 stack before
    /// setup gives up.
    const IPV6_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

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
        /// The adapter's LUID, the key of its IP Helper rows.
        luid: u64,
        name: String,
        mtu: u16,
        address: Ipv6Address,
    }

    impl TunDevice {
        /// Create a wintun TUN adapter and configure it with an IPv6 address.
        ///
        /// Loads the wintun DLL, creates (or reopens) a named adapter, starts
        /// a session with a 2 MiB ring buffer, and configures the interface
        /// through IP Helper. Requires Administrator privileges.
        pub async fn create(config: &TunConfig, address: Ipv6Address) -> Result<Self, TunError> {
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

            // SAFETY: every bit pattern of the LUID union is a valid u64.
            let luid = unsafe { adapter.get_luid().Value };
            configure_windows_interface(luid, address.to_ipv6(), mtu).await?;

            Ok(Self {
                session,
                _adapter: adapter,
                luid,
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

        /// Get the IPv6 address assigned to this device.
        pub fn address(&self) -> &Ipv6Address {
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
            drop_route(self.luid)
        }

        /// Create a TunWriter for this device.
        ///
        /// Clones the wintun session `Arc` so the writer can allocate and send
        /// packets independently. Returns the writer and a channel sender for
        /// submitting packets to be written.
        ///
        /// `max_mss` is the adapter's TCP MSS ceiling, shared live so a
        /// transport that binds or unbinds after start moves it (see
        /// [`MssCeiling`]). `path_mtu_lookup` is the adapter's copy of the
        /// per-peer payload limits, filled from the node's messages on the
        /// link.
        pub fn create_writer(
            &self,
            max_mss: MssCeiling,
            path_mtu_lookup: PathMtuReplica,
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
    /// Also performs TCP MSS clamping on inbound SYN-flagged packets (SYN and SYN-ACK).
    pub struct TunWriter {
        session: Arc<wintun::Session>,
        rx: mpsc::Receiver<Vec<u8>>,
        name: String,
        max_mss: MssCeiling,
        path_mtu_lookup: PathMtuReplica,
    }

    impl TunWriter {
        /// Run the writer loop.
        ///
        /// Blocks forever, reading packets from the channel and writing them
        /// to the wintun session. Returns when the channel is closed.
        pub fn run(self) {
            use super::per_flow_max_mss;
            use crate::ipv6tun::tcp_mss::clamp_tcp_mss;

            debug!(
                name = %self.name,
                max_mss = self.max_mss.load(std::sync::atomic::Ordering::Relaxed),
                "TUN writer starting"
            );

            for mut packet in self.rx {
                // Read per packet, not once: a transport binding or unbinding
                // moves the node's egress floor. See `MssCeiling`.
                let global_max_mss = self.max_mss.load(std::sync::atomic::Ordering::Relaxed);
                // Per-destination clamp (peer source IPv6 = bytes 8..24)
                let effective_max_mss = if packet.len() >= 24 {
                    per_flow_max_mss(&self.path_mtu_lookup, &packet[8..24], global_max_mss)
                } else {
                    global_max_mss
                };
                // Clamp TCP MSS on inbound SYN-flagged packets
                if clamp_tcp_mss(&mut packet, effective_max_mss) {
                    trace!(
                        name = %self.name,
                        max_mss = effective_max_mss,
                        "Clamped TCP MSS in inbound SYN packet"
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
    pub(crate) fn run_tun_reader(
        mut device: TunDevice,
        mtu: u16,
        our_addr: Ipv6Address,
        tun_tx: TunTx,
        host: super::HostPath,
        max_mss: MssCeiling,
        path_mtu_lookup: PathMtuReplica,
    ) {
        let (name, mut buf) = super::tun_reader_setup(device.name(), mtu, &max_mss);

        loop {
            match device.read_packet(&mut buf) {
                Ok(n) if n > 0 => {
                    if !super::handle_tun_packet(
                        &mut buf[..n],
                        max_mss.load(std::sync::atomic::Ordering::Relaxed),
                        &name,
                        our_addr,
                        &tun_tx,
                        &host,
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
    /// Removes the fd00::/8 route from the adapter named [`ADAPTER_NAME`].
    /// The wintun adapter itself is cleaned up when the `Adapter` handle is
    /// dropped. An adapter that is already gone is not an error.
    pub async fn shutdown_tun_interface(name: &str) -> Result<(), TunError> {
        debug!("Shutting down TUN interface {}", name);
        // `name` is the tunnel type; the adapter is found by its alias. The
        // lookup's one documented failure is an invalid parameter, which
        // for this fixed alias means no interface carries it.
        match super::super::winnet::alias_luid(ADAPTER_NAME) {
            Ok(luid) => drop_route(luid)?,
            Err(e) => debug!("no adapter named {ADAPTER_NAME} ({e}); no route to remove"),
        }
        debug!("TUN interface {} stopped", name);
        Ok(())
    }

    /// Remove the fd00::/8 route from adapter `luid`; its absence is not an
    /// error.
    fn drop_route(luid: u64) -> Result<(), TunError> {
        let (dst, len) = MESH_PREFIX;
        super::super::winnet::delete_route(luid, dst, len)
            .map(|_| ())
            .map_err(|e| TunError::Configure(format!("failed to delete route {dst}/{len}: {e}")))
    }

    /// Configure the Windows network interface with IPv6 address, MTU, and
    /// route, through IP Helper.
    ///
    /// Waits, for up to [`IPV6_WAIT`], for the new adapter to appear in the
    /// IPv6 stack. The address or route already present is not an error;
    /// any other failure is, with the Win32 error code in the message, so
    /// that `open_tun` continues without a TUN as on the other platforms.
    async fn configure_windows_interface(
        luid: u64,
        addr: Ipv6Addr,
        mtu: u16,
    ) -> Result<(), TunError> {
        use super::super::winnet::{self, Created};

        let start = std::time::Instant::now();
        loop {
            match winnet::ipv6_present(luid) {
                Ok(true) => break,
                Ok(false) if start.elapsed() < IPV6_WAIT => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Ok(false) => {
                    return Err(TunError::Configure(format!(
                        "adapter {ADAPTER_NAME} has no IPv6 interface after {IPV6_WAIT:?}; is IPv6 enabled on it?"
                    )));
                }
                Err(e) => {
                    return Err(TunError::Configure(format!(
                        "failed to read the IPv6 interface of {ADAPTER_NAME}: {e}"
                    )));
                }
            }
        }

        let fail =
            |what: String| move |e: std::io::Error| TunError::Configure(format!("{what}: {e}"));
        if winnet::add_address(luid, addr, 128)
            .map_err(fail(format!("failed to add {addr}/128 to {ADAPTER_NAME}")))?
            == Created::Exists
        {
            debug!("{addr}/128 already on {ADAPTER_NAME}");
        }
        winnet::set_mtu(luid, u32::from(mtu)).map_err(fail(format!(
            "failed to set the IPv6 MTU of {ADAPTER_NAME} to {mtu}"
        )))?;
        let (dst, len) = MESH_PREFIX;
        if winnet::add_route(luid, dst, len).map_err(fail(format!(
            "failed to add route {dst}/{len} via {ADAPTER_NAME}"
        )))? == Created::Exists
        {
            debug!("route {dst}/{len} already on {ADAPTER_NAME}");
        }
        Ok(())
    }
}

// Re-export Windows TUN types at module level
#[cfg(windows)]
pub(crate) use windows_tun::run_tun_reader;
#[cfg(windows)]
pub use windows_tun::{TunDevice, TunWriter, shutdown_tun_interface};

// Android uses an app-owned TUN (the embedder owns the fd, e.g. an Android
// VpnService); FIPS never creates or configures a system TUN here. These no-op
// stubs stand in for the platform ops so the shared TunDevice code compiles.
#[cfg(target_os = "android")]
mod platform {
    use super::TunError;
    use std::net::Ipv6Addr;

    pub fn is_ipv6_disabled() -> bool {
        false
    }
    pub async fn delete_interface(_name: &str) -> Result<(), TunError> {
        Ok(())
    }
    pub async fn configure_interface(
        _name: &str,
        _addr: Ipv6Addr,
        _mtu: u16,
    ) -> Result<(), TunError> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::TunError;
    use futures::TryStreamExt;
    use rtnetlink::packet_route::rule::RuleAttribute;
    use rtnetlink::{Handle, LinkUnspec, RouteMessageBuilder, RuleAddRequest, new_connection};
    use std::net::Ipv6Addr;
    use tracing::{debug, warn};

    /// Check if IPv6 is disabled system-wide.
    pub fn is_ipv6_disabled() -> bool {
        std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
            .map(|s| s.trim() == "1")
            .unwrap_or(false)
    }

    /// Refuse an existing interface named `name` unless it is a TUN.
    ///
    /// Passes when no link of that name exists, or when it is a TUN, which
    /// create then reopens (unheld) or fails on (held). Any other link, or
    /// one whose kind cannot be read, is refused and left untouched.
    pub async fn refuse_foreign_link(name: &str) -> Result<(), TunError> {
        use rtnetlink::packet_route::link::{LinkAttribute, LinkInfo};
        let (connection, handle, _) = new_connection()
            .map_err(|e| TunError::Configure(format!("netlink connection failed: {}", e)))?;
        tokio::spawn(connection);

        let mut links = handle.link().get().match_name(name.to_string()).execute();
        let link = match links.try_next().await {
            Ok(Some(link)) => link,
            Ok(None) => return Ok(()),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ENODEV => {
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        let kind = link.attributes.iter().find_map(|attr| match attr {
            LinkAttribute::LinkInfo(infos) => infos.iter().find_map(|info| match info {
                LinkInfo::Kind(kind) => Some(kind),
                _ => None,
            }),
            _ => None,
        });
        existing_link_verdict(name, kind)
    }

    /// Whether create may use an existing link named `name` of link kind
    /// `kind`: only a TUN. A link with no kind (a physical interface) is
    /// refused along with every other kind.
    pub fn existing_link_verdict(
        name: &str,
        kind: Option<&rtnetlink::packet_route::link::InfoKind>,
    ) -> Result<(), TunError> {
        use rtnetlink::packet_route::link::InfoKind;
        match kind {
            Some(InfoKind::Tun) => Ok(()),
            Some(kind) => Err(TunError::Configure(format!(
                "an interface named {name} already exists and is not a TUN ({kind}); \
                 refusing to use it"
            ))),
            None => Err(TunError::Configure(format!(
                "an interface named {name} already exists and is not a TUN (no link kind, \
                 such as a physical interface); refusing to use it"
            ))),
        }
    }

    /// Delete the TUN named `name` and the `fd00::/8` policy rule
    /// `configure_interface` added.
    ///
    /// The rule is removed even when the interface cannot be found or
    /// deleted, and that error is returned afterwards.
    pub async fn delete_interface(name: &str) -> Result<(), TunError> {
        let (connection, handle, _) = new_connection()
            .map_err(|e| TunError::Configure(format!("netlink connection failed: {}", e)))?;
        tokio::spawn(connection);

        let deleted = match get_interface_index(&handle, name).await {
            Ok(index) => handle
                .link()
                .del(index)
                .execute()
                .await
                .map_err(TunError::from),
            Err(e) => Err(e),
        };
        remove_rule(&handle).await;
        deleted
    }

    /// The `fd00::/8` policy rule `configure_interface` adds, without its
    /// `suppress_prefixlength`. The one place the rule's match is written,
    /// so the add and the delete cannot drift apart.
    fn mesh_rule(handle: &Handle) -> RuleAddRequest<Ipv6Addr> {
        let mut req = handle
            .rule()
            .add()
            .v6()
            .destination_prefix(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 8)
            .table_id(254)
            .priority(5265);
        req.message_mut().header.action = 1.into(); // FR_ACT_TO_TBL
        req
    }

    /// Delete the `fd00::/8` policy rule, of the current shape or the one
    /// older versions added without `suppress_prefixlength`: a delete that
    /// names no `suppress_prefixlength` matches either, one per call. Stops
    /// at the first failure, `ENOENT` (none left) being the normal end, and
    /// after a few calls in any case.
    async fn remove_rule(handle: &Handle) {
        for _ in 0..8 {
            let mut req = mesh_rule(handle);
            let message = req.message_mut().clone();
            match handle.rule().del(message).execute().await {
                Ok(()) => {}
                Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ENOENT => return,
                Err(e) => {
                    debug!("ip6 rule for fd00::/8 not removed: {e}");
                    return;
                }
            }
        }
    }

    /// Configure a network interface with an IPv6 address via netlink.
    pub async fn configure_interface(name: &str, addr: Ipv6Addr, mtu: u16) -> Result<(), TunError> {
        let (connection, handle, _) = new_connection()
            .map_err(|e| TunError::Configure(format!("netlink connection failed: {}", e)))?;
        tokio::spawn(connection);

        // Get interface index
        let index = get_interface_index(&handle, name).await?;

        let fd_prefix: Ipv6Addr = "fd00::".parse().unwrap();
        let route = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(fd_prefix, 8)
            .output_interface(index)
            .build();
        clear_mesh_leftovers(&handle, index, route.clone()).await?;

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

        // Add route for fd00::/8 (mesh IPv6 address space) via this interface
        handle
            .route()
            .add(route)
            .execute()
            .await
            .map_err(|e| TunError::Configure(format!("failed to add fd00::/8 route: {}", e)))?;

        // Add ip6 rule to ensure fd00::/8 uses the main table, preventing other
        // routing software (e.g. Tailscale) from intercepting FIPS traffic via
        // catch-all rules in auxiliary routing tables.
        //
        // suppress_prefixlength 0 keeps main's default route from answering
        // through this rule, so the fd00::/8 route above still claims mesh
        // traffic while the node runs, but a rule left behind by an exit
        // without stop (a crash or kill) sends other ULA traffic on to the
        // table that owns it rather than out the default route. Any rule of
        // either shape an earlier run left is removed first. This comes
        // after the route add, so a create that fails there (another node's
        // TUN already owns fd00::/8 in this namespace) leaves that node's
        // rule alone.
        remove_rule(&handle).await;
        let mut rule_req = mesh_rule(&handle);
        rule_req
            .message_mut()
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(0));
        match rule_req.execute().await {
            Ok(()) => {}
            // A kernel without IPv6 policy routing.
            Err(rtnetlink::Error::NetlinkError(e))
                if e.raw_code() == -libc::EAFNOSUPPORT || e.raw_code() == -libc::EOPNOTSUPP =>
            {
                debug!("ip6 rule for fd00::/8 not added: {e}");
            }
            Err(e) => warn!("ip6 rule for fd00::/8 not added: {e}"),
        }

        Ok(())
    }

    /// Remove what an earlier node left on a reopened persistent TUN when it
    /// exited without stopping (killed or crashed): its `fd00::/8` /128
    /// mesh addresses and its `fd00::/8` route through this interface.
    /// Without this the address or route add that follows fails with
    /// `EEXIST` and the node runs without a TUN. A new TUN has neither, and
    /// nothing on another interface is touched.
    async fn clear_mesh_leftovers(
        handle: &Handle,
        index: u32,
        route: rtnetlink::packet_route::route::RouteMessage,
    ) -> Result<(), TunError> {
        use rtnetlink::packet_route::address::AddressAttribute;
        use std::net::IpAddr;

        let leftovers: Vec<_> = handle
            .address()
            .get()
            .set_link_index_filter(index)
            .set_prefix_length_filter(128)
            .execute()
            .try_filter(|msg| {
                let mesh = msg.attributes.iter().any(|attr| match attr {
                    AddressAttribute::Address(IpAddr::V6(a)) => a.octets()[0] == 0xfd,
                    _ => false,
                });
                futures::future::ready(mesh)
            })
            .try_collect()
            .await?;
        for msg in leftovers {
            debug!("removing a mesh address an earlier run left on TUN index {index}");
            handle.address().del(msg).execute().await?;
        }

        match handle.route().del(route).execute().await {
            Ok(()) => debug!("removed an fd00::/8 route an earlier run left on TUN index {index}"),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ESRCH => {}
            Err(e) => {
                return Err(TunError::Configure(format!(
                    "failed to remove a leftover fd00::/8 route: {e}"
                )));
            }
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

/// Interface configuration on macOS and FreeBSD. Visible to the parent
/// module so the `bsdnet` root tests can run `configure_interface` a second
/// time on a configured device.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) mod platform {
    use super::TunError;
    use crate::ipv6tun::bsdnet;
    use std::net::Ipv6Addr;

    /// The mesh address space routed into the TUN: `fd00::/8`.
    const MESH_PREFIX: (Ipv6Addr, u8) = (Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 8);

    /// Check if IPv6 is disabled system-wide.
    ///
    /// macOS: `net.inet6.ip6.disabled` is 1 when IPv6 is turned off; a
    /// kernel without that name, or any failure to read it, counts as
    /// enabled.
    #[cfg(target_os = "macos")]
    pub fn is_ipv6_disabled() -> bool {
        matches!(bsdnet::sysctl_int("net.inet6.ip6.disabled"), Ok(1))
    }

    /// Check if IPv6 is disabled system-wide.
    ///
    /// FreeBSD: `kern.features.inet6` is 1 when the kernel has IPv6 support.
    /// On a kernel built without INET6 the name is absent (`ENOENT`), so any
    /// failure to read it, or any other value, means disabled.
    #[cfg(target_os = "freebsd")]
    pub fn is_ipv6_disabled() -> bool {
        !matches!(bsdnet::sysctl_int("kern.features.inet6"), Ok(1))
    }

    /// Take a network interface down at shutdown, by clearing `IFF_UP`.
    ///
    /// This does not wake a reader blocked on the device; the shutdown pipe
    /// does (see `run_tun_reader`).
    pub async fn delete_interface(name: &str) -> Result<(), TunError> {
        bsdnet::set_up(name, false)
            .map_err(|e| TunError::Configure(format!("failed to take {name} down: {e}")))
    }

    /// Configure the TUN interface: its `/128` address, on FreeBSD IPv6
    /// enabled on it, the interface up, and the `fd00::/8` route through it.
    ///
    /// The MTU was set by the `tun` crate when it created the device.
    pub async fn configure_interface(
        name: &str,
        addr: Ipv6Addr,
        _mtu: u16,
    ) -> Result<(), TunError> {
        bsdnet::add_address(name, addr, 128)
            .map_err(|e| TunError::Configure(format!("failed to add {addr}/128 to {name}: {e}")))?;

        // FreeBSD: a manually-configured interface with no autoconf
        // link-local comes up with ND6_IFF_IFDISABLED set, which silently
        // drops all IPv6.
        #[cfg(target_os = "freebsd")]
        bsdnet::enable_inet6(name)
            .map_err(|e| TunError::Configure(format!("failed to enable IPv6 on {name}: {e}")))?;

        bsdnet::set_up(name, true)
            .map_err(|e| TunError::Configure(format!("failed to bring {name} up: {e}")))?;

        let ifindex = bsdnet::interface_index(name)
            .map_err(|e| TunError::Configure(format!("no index for {name}: {e}")))?;
        let (dst, len) = MESH_PREFIX;
        bsdnet::ensure_route(dst, len, ifindex).map_err(|e| {
            TunError::Configure(format!("failed to add route {dst}/{len} via {name}: {e}"))
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "tests/tun.rs"]
mod name_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::RwLock;

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

    fn fips_addr_with_node_byte(b: u8) -> Ipv6Address {
        let mut bytes = [0u8; 16];
        bytes[0] = crate::identity::IPV6_ADDRESS_PREFIX;
        bytes[1] = b;
        Ipv6Address::from_bytes(bytes).unwrap()
    }

    fn empty_lookup() -> PathMtuReplica {
        Arc::new(RwLock::new(HashMap::new()))
    }

    /// The payload limit the node reports for a stored path MTU of `mtu`.
    fn held(mtu: u16) -> u16 {
        crate::node::path_mtu::payload_limit(mtu)
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
        lookup.write().unwrap().insert(addr, held(1280));
        assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1360), 1143);
    }

    #[test]
    fn per_flow_keeps_global_when_path_mtu_larger() {
        // Discovery learned path_mtu=1452 (> global). Per-flow stays at
        // global 1143 (the smaller of the two).
        let lookup = empty_lookup();
        let addr = fips_addr_with_node_byte(0x42);
        lookup.write().unwrap().insert(addr, held(1452));
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
        lookup.write().unwrap().insert(addr, held(1452));
        // global=1360, path_max = 1452-77-60 = 1315; min(1360, 1315) = 1315.
        // 1315 > 1143, so the conservative ceiling did NOT clamp here.
        assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1360), 1315);
    }

    #[test]
    fn per_flow_stored_mtu_admitting_no_payload_byte_falls_back_to_conservative_ceiling() {
        // A stored MTU of 137 or less leaves nothing after the 77 bytes of
        // FIPS encapsulation and the 40 + 20 bytes of IPv6 and TCP header, so
        // the MSS arithmetic saturates to zero. Returning that zero would be
        // worse than the fallback: `clamp_tcp_mss` refuses a ceiling of zero,
        // so the SYN would go out at the kernel-natural MSS, unclamped.
        for stored in [0u16, 1, 100, 137] {
            let lookup = empty_lookup();
            let addr = fips_addr_with_node_byte(0x42);
            lookup.write().unwrap().insert(addr, held(stored));
            assert_eq!(
                per_flow_max_mss(&lookup, addr.as_bytes(), 1360),
                1143,
                "stored path_mtu {stored} admits no payload byte and must be ignored"
            );
        }
    }

    #[test]
    fn per_flow_honors_a_locally_seeded_sub_floor_mtu_instead_of_loosening_to_the_ceiling() {
        // Only `seed_path_mtu_for_link_peer` can put a sub-floor value in this
        // map: every remote-supplied path MTU is refused at ingress, at the
        // path MTU state machine, the reactive `MtuExceeded` write and the
        // discovery response. A seeded value is therefore the node's own link
        // measurement, and BLE negotiates one per connection that lands in
        // this band routinely.
        //
        // Applying the remote-value floor here discarded it and advertised
        // 1143 instead, which a link this narrow cannot carry: every full-size
        // segment is refused by the transport, a direct link has no forwarder
        // to answer with `MtuExceeded`, and the flow stalls with no feedback.
        // The tight clamp is the whole reason the seed exists.
        //
        // 138 is the first MTU admitting a payload byte; 240 is a plausible
        // negotiated BLE value; 255 is one below the remote-value floor. The
        // whole table is evaluated before asserting, so a regression names
        // every band it broke rather than only the first.
        let want = [(138u16, 1u16), (240, 103), (255, 118)];
        let got: Vec<(u16, u16)> = want
            .iter()
            .map(|&(stored, _)| {
                let lookup = empty_lookup();
                let addr = fips_addr_with_node_byte(0x42);
                lookup.write().unwrap().insert(addr, held(stored));
                (stored, per_flow_max_mss(&lookup, addr.as_bytes(), 1360))
            })
            .collect();
        assert_eq!(
            got,
            want.to_vec(),
            "each locally seeded path_mtu must clamp tight, not fall back to 1143"
        );
    }

    #[test]
    fn per_flow_stored_mtu_at_the_actionable_floor_is_still_honored() {
        // The smallest value the node will accept from a remote party still
        // clamps to its own arithmetic and nothing coarser: 256 - 77 - 40 - 20
        // = 119. Reintroducing the remote-value floor as a clamp-time guard
        // would leave this case passing, so it is pinned separately from the
        // sub-floor table above.
        let lookup = empty_lookup();
        let addr = fips_addr_with_node_byte(0x42);
        lookup
            .write()
            .unwrap()
            .insert(addr, held(crate::proto::mmp::MIN_ACTIONABLE_PATH_MTU));
        assert_eq!(per_flow_max_mss(&lookup, addr.as_bytes(), 1360), 119);
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
        lookup.write().unwrap().insert(a, held(1280));
        lookup.write().unwrap().insert(b, held(1452));
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
    /// to `dst`, sourced from a distinct mesh IPv6 address.
    fn ipv6_packet_to(dst: &Ipv6Address) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60; // version 6
        pkt[6] = 59; // next header = No Next Header (skips MSS clamp)
        pkt[7] = 64; // hop limit
        pkt[8] = crate::identity::IPV6_ADDRESS_PREFIX; // src in fd::/8
        pkt[24..40].copy_from_slice(dst.as_bytes()); // dst
        pkt
    }

    /// A host path whose map knows `peer`, and the node's end of its
    /// datagram channel.
    fn host_path(
        peer: Option<crate::ipv6tun::link::PeerKey>,
    ) -> (
        HostPath,
        tokio::sync::mpsc::Receiver<crate::ipv6tun::link::Datagram>,
    ) {
        let state = crate::ipv6tun::core::MeshState::new();
        if let Some(peer) = peer {
            state.apply(crate::ipv6tun::link::FromMesh::KnownKey { peer });
        }
        let (datagrams, rx) = tokio::sync::mpsc::channel(4);
        let limiter = Arc::new(std::sync::Mutex::new(
            crate::ipv6tun::icmp_rate_limit::IcmpRateLimiter::new(),
        ));
        (
            HostPath {
                state,
                limiter,
                datagrams,
            },
            rx,
        )
    }

    #[test]
    fn self_addressed_packet_is_hairpinned_to_tun() {
        let our_addr = fips_addr_with_node_byte(0x55);
        let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>();
        let (outbound_tx, mut outbound_rx) = host_path(None);
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
        let key = crate::ipv6tun::link::any_key();
        let peer = key.address();
        let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>();
        let (outbound_tx, mut outbound_rx) = host_path(Some(key));
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
    // macOS utun / FreeBSD TUNSIFHEAD packet-info header (4-byte big-endian
    // AF prefix)
    //
    // These tests are pure-data byte-buffer manipulation and require no
    // privilege, no actual TUN device, no system calls. They pin the wire
    // format that `TunWriter::run` emits ahead of every IPv6 frame on the
    // dup'd fd, and the inverse parse `read_packet` uses on FreeBSD.
    // ========================================================================

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    mod utun_header {
        use super::super::{UTUN_AF_INET6, parse_utun_af_prefix, utun_af_inet6_header};

        #[test]
        fn af_inet6_constant_matches_platform() {
            // <sys/socket.h> defines AF_INET6 = 30 on Darwin and 28 on
            // FreeBSD. If this ever diverges, every TUN write FIPS issues
            // will be misclassified by the kernel and dropped, and every
            // inbound frame will be skipped as non-IPv6.
            #[cfg(target_os = "macos")]
            assert_eq!(UTUN_AF_INET6, 30);
            #[cfg(target_os = "freebsd")]
            assert_eq!(UTUN_AF_INET6, 28);
            assert_eq!(libc::AF_INET6 as u32, UTUN_AF_INET6);
        }

        #[test]
        fn encode_produces_big_endian_af_inet6() {
            // The kernel reads the 4-byte prefix as a big-endian u32:
            // 30 == 0x0000001e (Darwin), 28 == 0x0000001c (FreeBSD).
            let header = utun_af_inet6_header();
            #[cfg(target_os = "macos")]
            assert_eq!(header, [0x00, 0x00, 0x00, 0x1e]);
            #[cfg(target_os = "freebsd")]
            assert_eq!(header, [0x00, 0x00, 0x00, 0x1c]);
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
