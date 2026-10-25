//! Start and stop of the TUN and DNS children.
//!
//! The node's supervisor decides when each child starts and stops, and in
//! what order. The bodies that bring the TUN device and the `.fips` DNS
//! responder up and take them down live here, together with the handles
//! they leave behind for the node to drive and, later, to tear down.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

use super::config::{DnsConfig, TunConfig};
use super::core::{Applied, MeshState, PathMtuReplica, run_link};
use super::dns::{MeshSide, bind_dns_socket, lookup_mesh_ifindex, run_responder};
use super::icmp::IcmpContext;
use super::icmp_rate_limit::IcmpRateLimiter;
use super::link::{Attach, Datagram, Feeds, FromMesh, IPV6_PORT, Learned, MeshLink, Refusal};
use super::outbound::{answer, outbound};
use super::tun::{
    HostPath, MssCeiling, TunDevice, TunError, TunOutboundRx, TunState, TunTx, run_tun_reader,
    shutdown_tun_interface,
};
use crate::Ipv6Address;
use crate::config::PeerConfig;
use crate::hosts::{DEFAULT_HOSTS_PATH, HostMap, HostMapReloader};
use crate::node::lifecycle::supervisor::Child;
use crate::node::lifecycle::{report_exit, report_thread};

/// What the DNS mesh filter judges by when the mesh interface's index is
/// unknown, as the start-up warning names it.
#[cfg(unix)]
const DNS_MESH_FALLBACK: &str = "the destination address";
#[cfg(not(unix))]
const DNS_MESH_FALLBACK: &str = "the mesh source address";

/// State and runtime handles of the TUN and DNS children, held by the
/// node's supervisor.
///
/// Our address, the TUN state and the ICMPv6 limiter are set when the node
/// is built. Every other field is empty until its child starts. The TUN
/// channels are the exception: an embedder that owns the TUN installs them
/// before start through `Node::enable_app_owned_tun`, without a device name.
pub(crate) struct Handles {
    /// This node's IPv6 address, the source of the Destination Unreachable
    /// replies sent to the host. Set when the node is built and again from
    /// the node's key when it attaches us; the node's identity never
    /// changes, so the two agree.
    our_addr: Ipv6Addr,
    /// What the node has told us over the link: the payload limits the TUN
    /// threads clamp by.
    mesh: MeshState,
    /// Our end of the link, held from the attach until the task that applies
    /// the node's later messages starts.
    link: Option<MeshLink>,
    /// The task applying the node's messages, from when it starts until the
    /// node detaches us.
    link_task: Option<tokio::task::JoinHandle<()>>,
    /// Whether the node has attached us since it last detached us. Neither
    /// the device nor its threads may start before the attach.
    attached: bool,
    /// Where the adapter's datagrams go: the node's end, from the attach.
    datagrams: Option<Sender<Datagram>>,
    /// Where the DNS responder reports the keys it learned: the node's end,
    /// from the attach.
    learned: Option<Sender<Learned>>,
    /// Whether the attach asked for the identity feed, so that our key map
    /// is kept: only then does the node tell us what to forget.
    keys_fed: bool,
    /// TUN device state, as reported by `Node::tun_state`.
    tun_state: TunState,
    /// Per-source limiter of the Packet Too Big replies sent to the host,
    /// shared with the TUN reader thread.
    icmp_limiter: Arc<Mutex<IcmpRateLimiter>>,

    /// Kernel name of the TUN device this node created, used to delete or
    /// down it at teardown. Set only while a system TUN is up; an app-owned
    /// TUN leaves it unset.
    pub(crate) tun_name: Option<String>,
    /// TUN packet sender channel.
    pub(crate) tun_tx: Option<TunTx>,
    /// Receiver of the packets an embedder that owns the TUN sends.
    pub(crate) tun_outbound_rx: Option<TunOutboundRx>,
    /// TUN reader thread handle.
    pub(crate) tun_reader_handle: Option<JoinHandle<()>>,
    /// TUN writer thread handle.
    pub(crate) tun_writer_handle: Option<JoinHandle<()>>,
    /// Shutdown pipe: writing to this fd unblocks the TUN reader thread on
    /// macOS and FreeBSD. On Linux, deleting the interface via netlink
    /// serves the same purpose.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    pub(crate) tun_shutdown_fd: Option<std::os::unix::io::RawFd>,

    /// DNS responder task handle.
    pub(crate) dns_task: Option<tokio::task::JoinHandle<()>>,
    /// Address the DNS responder actually bound, read back from the socket
    /// after `bind` so a port-0 config resolves to the assigned port. `Some`
    /// only while the responder is up; published to embedders through
    /// [`Node::dns_local_addr`](crate::Node::dns_local_addr).
    pub(crate) dns_local_addr: Option<SocketAddr>,
    /// Sends a new peer-alias base to the running DNS responder; `Some` only
    /// while it runs. Written through [`Handles::publish_aliases`].
    dns_aliases: Option<tokio::sync::watch::Sender<HostMap>>,
}

/// What the TUN threads take from the node when they start.
pub(crate) struct TunThreads {
    /// Sender each TUN thread reports `Child::Tun` on when it exits.
    pub(crate) exit_tx: Option<Sender<Child>>,
    /// How many packets toward the host the writer's queue holds
    /// (`node.buffers.host_channel`).
    pub(crate) capacity: usize,
}

impl Handles {
    /// Empty handles for a node whose address is `our_addr`, with the TUN
    /// configured when `tun_enabled` and disabled otherwise.
    pub(crate) fn new(our_addr: Ipv6Addr, tun_enabled: bool) -> Self {
        Self {
            our_addr,
            tun_state: if tun_enabled {
                TunState::Configured
            } else {
                TunState::Disabled
            },
            icmp_limiter: Arc::new(Mutex::new(IcmpRateLimiter::new())),
            mesh: MeshState::new(),
            datagrams: None,
            learned: None,
            keys_fed: false,
            link: None,
            link_task: None,
            attached: false,
            tun_name: None,
            tun_tx: None,
            tun_outbound_rx: None,
            tun_reader_handle: None,
            tun_writer_handle: None,
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            tun_shutdown_fd: None,
            dns_task: None,
            dns_local_addr: None,
            dns_aliases: None,
        }
    }

    /// The TUN device state.
    pub(crate) fn tun_state(&self) -> TunState {
        self.tun_state
    }

    /// Borrow the host-facing ICMPv6 sender: the TUN channel, our address
    /// and the Packet Too Big rate limiter.
    pub(crate) fn icmp(&self) -> IcmpContext<'_> {
        IcmpContext::new(self.tun_tx.as_ref(), self.our_addr, &self.icmp_limiter)
    }

    /// Run the host half for one packet an embedder that owns the TUN sent:
    /// answer it here, or return the datagram for the node.
    pub(crate) fn outbound(&mut self, packet: &[u8]) -> Option<Datagram> {
        self.catch_up();
        outbound(packet, &self.mesh, &mut self.icmp())
    }

    /// Answer the host for a datagram the node refused.
    pub(crate) fn answer(&self, refusal: Refusal) {
        answer(refusal, &mut self.icmp());
    }

    /// What to ask the node for when it attaches us: port 256, the path MTU
    /// feed and the identity feed while the TUN is enabled, and nothing
    /// otherwise.
    pub(crate) fn attach_request(&self) -> Attach {
        let tun = self.tun_state != TunState::Disabled;
        Attach {
            port: tun.then_some(IPV6_PORT),
            feeds: Feeds {
                path_mtu: tun,
                identity: tun,
            },
        }
    }

    /// Take our end of the link from the node's attach, applying everything
    /// up to the end of its replay now, before any device opens.
    pub(crate) fn attached(&mut self, link: MeshLink, feeds: Feeds) {
        self.attached = true;
        self.keys_fed = feeds.identity;
        self.datagrams = Some(link.datagrams.clone());
        self.learned = Some(link.learned.clone());
        self.link = Some(link);
        while let Some(message) = self.next_queued() {
            match self.mesh.apply(message) {
                Applied::Attached(addr) => self.our_addr = addr,
                Applied::Synced => break,
                Applied::State => {}
            }
        }
    }

    /// Apply every message the node has queued so far.
    fn catch_up(&mut self) {
        while let Some(message) = self.next_queued() {
            if let Applied::Attached(addr) = self.mesh.apply(message) {
                self.our_addr = addr;
            }
        }
    }

    /// The next message already queued on the held link, if any.
    fn next_queued(&mut self) -> Option<FromMesh> {
        self.link.as_mut()?.from_mesh.try_recv().ok()
    }

    /// Start the task that applies the node's messages from now on, unless
    /// it already runs. The node's start calls this once its children are
    /// up; starting the TUN threads calls it earlier.
    pub(crate) fn run_link(&mut self) {
        self.catch_up();
        if let Some(link) = self.link.take() {
            self.link_task = Some(tokio::spawn(run_link(link, self.mesh.clone())));
        }
    }

    /// Wait for the node's messages to stop, once the node has dropped its
    /// end of the link: the task applies what is still queued and ends.
    ///
    /// The next attach clears and replays our copy, so nothing a previous
    /// start queued may be applied after it; waiting here is what rules
    /// that out.
    pub(crate) async fn detached(&mut self) {
        self.attached = false;
        self.datagrams = None;
        self.learned = None;
        self.link = None;
        if let Some(task) = self.link_task.take()
            && let Err(e) = task.await
        {
            debug!(error = %e, "IPv6 adapter link task ended abnormally");
        }
    }

    /// What the TUN threads clamp by: the ceiling, the node-wide IPv6 MTU
    /// and the per-peer limits, with every message the node has queued so
    /// far applied first, so neither thread starts on older values.
    fn clamp_inputs(&mut self) -> (MssCeiling, u16, PathMtuReplica) {
        self.catch_up();
        (self.mesh.ceiling(), self.mesh.ipv6_mtu(), self.mesh.paths())
    }

    /// The state the node's messages have left so far, without applying
    /// anything still queued, for tests.
    #[cfg(test)]
    pub(crate) fn mesh(&self) -> &MeshState {
        &self.mesh
    }

    /// Whether the node has attached us since it last detached us.
    #[cfg(test)]
    pub(crate) fn is_attached(&self) -> bool {
        self.attached
    }

    /// Apply every message the node has queued so far, for tests.
    #[cfg(test)]
    pub(crate) fn settle(&mut self) {
        self.catch_up();
    }

    /// What the DNS responder learns keys through, once attached, for tests.
    #[cfg(test)]
    pub(crate) fn learner(&self) -> Option<Learner> {
        Some(Learner {
            state: self.mesh.clone(),
            learned: self.learned.clone()?,
            keep: self.keys_fed,
        })
    }

    /// Where a system TUN reader sends its datagrams, once attached, for
    /// tests that stand in for the reader thread.
    #[cfg(test)]
    pub(crate) fn datagram_sender(&self) -> Option<Sender<Datagram>> {
        self.datagrams.clone()
    }

    /// The state once every queued message is applied, as the TUN threads
    /// would start with it, for tests.
    #[cfg(test)]
    pub(crate) fn applied(&mut self) -> (MssCeiling, u16, PathMtuReplica) {
        self.clamp_inputs()
    }

    /// Install the channels of a TUN the embedder owns, which makes the TUN
    /// active without a device.
    pub(crate) fn install_app_tun(&mut self, tun_tx: TunTx, outbound_rx: TunOutboundRx) {
        self.tun_tx = Some(tun_tx);
        self.tun_outbound_rx = Some(outbound_rx);
        self.tun_state = TunState::Active;
    }

    /// Create the TUN device, logging it, or log the failure, mark the TUN
    /// failed and return `None`.
    ///
    /// A failure here is not fatal to the node: it continues without a TUN.
    pub(crate) async fn open_tun(
        &mut self,
        config: &TunConfig,
        address: Ipv6Address,
    ) -> Option<TunDevice> {
        debug_assert!(self.attached, "the TUN device opened before the attach");
        match TunDevice::create(config, address).await {
            Ok(device) => {
                info!("TUN device active:");
                info!("     name: {}", device.name());
                info!("  address: {}", device.address());
                info!("      mtu: {}", device.mtu());
                Some(device)
            }
            Err(e) => {
                warn!(error = %e, "Failed to initialize TUN, continuing without it");
                self.tun_state = TunState::Failed;
                None
            }
        }
    }

    /// Whether the TUN child is up.
    ///
    /// Follows the device name, not the TUN sender: an app-owned TUN
    /// installs the sender but creates no device, so there is no TUN child
    /// to tear down.
    pub(crate) fn tun_up(&self) -> bool {
        self.tun_name.is_some()
    }

    /// Whether the DNS child is up: its responder task handle exists.
    pub(crate) fn dns_up(&self) -> bool {
        self.dns_task.is_some()
    }

    /// Resolve the index of the mesh TUN device this node actually created.
    ///
    /// Reads the device name recorded when the TUN was brought up, which is
    /// the kernel's name rather than the configured one. Returns `None` when
    /// no TUN is up, which disables the DNS responder's mesh-interface
    /// filter: with no mesh interface there is no mesh exposure to defend.
    /// An app-owned TUN also leaves the name unset, so the index is unknown
    /// there; the responder then filters by address (see
    /// [`Self::dns_mesh_side`]).
    pub(crate) fn mesh_ifindex(&self) -> Option<u32> {
        self.tun_name.as_deref().and_then(lookup_mesh_ifindex)
    }

    /// What the DNS responder needs to know of the mesh side: the mesh
    /// interface's index, and the node's own mesh address while a TUN is up,
    /// the daemon's own or an application-supplied one. The address lets the
    /// responder recognise a mesh query where the index is unknown.
    pub(crate) fn dns_mesh_side(&self) -> MeshSide {
        MeshSide {
            ifindex: self.mesh_ifindex(),
            addr: (self.tun_state == TunState::Active).then_some(self.our_addr),
        }
    }

    /// Start the TUN reader and writer threads on an opened device and keep
    /// their handles.
    ///
    /// An error here (the macOS/FreeBSD shutdown pipe, or duplicating the
    /// device fd for the writer) is fatal to the node's start, unlike a
    /// failure to create the device.
    pub(crate) fn spawn_tun(
        &mut self,
        device: TunDevice,
        threads: TunThreads,
    ) -> Result<(), TunError> {
        debug_assert!(self.attached, "the TUN threads started before the attach");
        let TunThreads { exit_tx, capacity } = threads;
        // Everything the node has said so far, including the limit it
        // published just before calling this, is in place before either
        // thread reads it.
        let (max_mss, effective_mtu, path_mtu_lookup) = self.clamp_inputs();
        let mtu = device.mtu();
        let name = device.name().to_string();
        let our_addr = *device.address();

        info!("effective MTU: {} bytes", effective_mtu);
        debug!(
            "   max TCP MSS: {} bytes",
            max_mss.load(std::sync::atomic::Ordering::Relaxed)
        );

        // On macOS and FreeBSD, create a shutdown pipe. Writing to it
        // unblocks the reader thread's select() loop without closing
        // the TUN fd (which would cause a double-close when TunDevice
        // drops). Linux instead unblocks the reader by deleting the
        // interface; on macOS/FreeBSD downing the interface does not
        // wake a blocked read.
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        let (shutdown_read_fd, shutdown_write_fd) = {
            let mut fds = [0i32; 2];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
                return Err(TunError::Configure("failed to create shutdown pipe".into()));
            }
            (fds[0], fds[1])
        };

        // Create writer (dups the fd for independent write access).
        // Pass the per-peer payload limits so the inbound SYN clamp can
        // honor a narrower path the node has learned.
        let (writer, tun_tx) =
            device.create_writer(max_mss.clone(), path_mtu_lookup.clone(), capacity)?;

        // Spawn writer thread. On exit, including a panic,
        // it self-reports `Child::Tun` (sync context →
        // `blocking_send`); TUN is one compound child, so
        // both threads reporting is fine (the FSM de-dups
        // via `up.remove`).
        let writer_child_tx = exit_tx.clone();
        let writer_handle = thread::spawn(move || {
            report_thread(Child::Tun, move || writer.run(), writer_child_tx.as_ref());
        });

        // Clone tun_tx for the reader
        let reader_tun_tx = tun_tx.clone();

        // The reader runs the host half itself and sends its datagrams to
        // the node on the link, whose channel the node bounded at
        // `node.buffers.tun_channel` when it attached us.
        let Some(datagrams) = self.datagrams.clone() else {
            return Err(TunError::Configure(
                "the TUN threads started before the attach".into(),
            ));
        };
        let host = HostPath {
            state: self.mesh.clone(),
            limiter: self.icmp_limiter.clone(),
            datagrams,
        };

        // Spawn reader thread. Like the writer, it
        // self-reports `Child::Tun` on exit or panic (sync
        // context → `blocking_send`). Exactly one cfg
        // variant compiles, so the exit sender is moved
        // into that closure.
        let reader_child_tx = exit_tx;
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        let reader_handle = thread::spawn(move || {
            report_thread(
                Child::Tun,
                move || {
                    run_tun_reader(
                        device,
                        mtu,
                        our_addr,
                        reader_tun_tx,
                        host,
                        max_mss,
                        path_mtu_lookup,
                        shutdown_read_fd,
                    )
                },
                reader_child_tx.as_ref(),
            );
        });
        #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
        let reader_handle = thread::spawn(move || {
            report_thread(
                Child::Tun,
                move || {
                    run_tun_reader(
                        device,
                        mtu,
                        our_addr,
                        reader_tun_tx,
                        host,
                        max_mss,
                        path_mtu_lookup,
                    )
                },
                reader_child_tx.as_ref(),
            );
        });

        self.tun_name = Some(name);
        self.tun_tx = Some(tun_tx);
        self.tun_reader_handle = Some(reader_handle);
        self.tun_writer_handle = Some(writer_handle);
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        {
            self.tun_shutdown_fd = Some(shutdown_write_fd);
        }
        self.tun_state = TunState::Active;
        self.run_link();
        Ok(())
    }

    /// Stop the TUN child: close the writer's channel, delete or down the
    /// interface, wake the reader, and join both threads.
    ///
    /// Marks the TUN disabled once both threads are joined. With no device
    /// name (never started, or app-owned) it does nothing, and an app-owned
    /// sender and its state are left in place.
    pub(crate) async fn stop_tun(&mut self) {
        let Some(name) = self.tun_name.take() else {
            return;
        };
        info!(name = %name, "Shutting down TUN interface");

        // Drop the tun_tx to signal the writer to stop
        self.tun_tx.take();

        // Delete the interface (on Linux, causes reader to get
        // EFAULT; on macOS/FreeBSD this downs it — the kernel
        // destroys the device once the reader closes the fd).
        if let Err(e) = shutdown_tun_interface(&name).await {
            warn!(name = %name, error = %e, "Failed to shutdown TUN interface");
        }

        // On macOS and FreeBSD, signal the reader thread to exit by
        // writing to the shutdown pipe. The reader's select() will
        // wake up and break.
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        if let Some(fd) = self.tun_shutdown_fd.take() {
            unsafe {
                libc::write(fd, b"x".as_ptr() as *const libc::c_void, 1);
                libc::close(fd);
            }
        }

        // Wait for threads to finish
        if let Some(handle) = self.tun_reader_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.tun_writer_handle.take() {
            let _ = handle.join();
        }
        self.tun_state = TunState::Disabled;
    }

    /// Start the `.fips` DNS responder and keep its handles, returning
    /// whether it came up. A failure is logged and is not fatal to the node.
    ///
    /// `peers` seeds the responder's own hosts map, which it reloads from
    /// the hosts file on its own. The keys it hands out go into our own map
    /// and to the node on the link, whose channel the node bounded at
    /// `node.buffers.dns_channel` when it attached us. Reads the TUN device
    /// name for the mesh-interface filter, so the TUN child, when enabled,
    /// starts first.
    pub(crate) fn start_dns(
        &mut self,
        config: &DnsConfig,
        peers: &[PeerConfig],
        exit_tx: Option<Sender<Child>>,
    ) -> bool {
        let Some(learned) = self.learned.clone() else {
            warn!("DNS responder not started: the node has not attached the IPv6 adapter");
            return false;
        };
        // Initialize DNS responder (independent of TUN).
        //
        // Default bind_addr is "::1" (IPv6 loopback). The shipped
        // fips-dns-setup configures systemd-resolved via a global
        // /etc/systemd/resolved.conf.d/fips.conf drop-in pointing at
        // [::1]:5354, which sidesteps a Linux IPV6_PKTINFO behaviour
        // where self-destined traffic to fips0's address is attributed
        // to fips0 in PKTINFO and gets silently dropped by the
        // mesh-interface filter in src/ipv6tun/dns.rs.
        //
        // A non-loopback bind_addr such as "::" answers every host
        // that can reach it. On Linux, macOS and FreeBSD, with the
        // daemon's own TUN, that same mesh-interface filter drops
        // queries arriving on the mesh interface, so mesh peers are
        // not served. Where the mesh index is unknown (an
        // application-supplied TUN, Windows, or a name that did not
        // resolve) and a TUN is up, the responder drops mesh
        // queries by address instead: those addressed to the
        // node's mesh address on unix, and those from a remote
        // fd00::/8 source on Windows (`mesh_query` in
        // src/ipv6tun/dns.rs).
        // `IPV6_V6ONLY=0` is set explicitly so IPv4 clients on
        // 127.0.0.1 still reach us regardless of kernel sysctl
        // defaults — but only when bind is on a wildcard / IPv6 path.
        let addr_str = config.bind_addr();
        match addr_str.parse::<IpAddr>() {
            Ok(ip) => {
                let bind = SocketAddr::new(ip, config.port());
                match bind_dns_socket(bind) {
                    Ok(socket) => {
                        // Read the bound address back off the socket
                        // rather than reusing `bind`: a port-0 config
                        // resolves to the kernel-assigned port here,
                        // and this is the address an embedder that
                        // proxies queries to us has to dial.
                        let local_addr = socket.local_addr().unwrap_or(bind);
                        let keys = Learner {
                            state: self.mesh.clone(),
                            learned,
                            keep: self.keys_fed,
                        };
                        let dns_ttl = config.ttl();
                        let base_hosts = HostMap::from_peer_configs(peers);
                        let hosts_path = PathBuf::from(DEFAULT_HOSTS_PATH);
                        let (aliases_tx, aliases_rx) =
                            tokio::sync::watch::channel(base_hosts.clone());
                        let reloader = HostMapReloader::new(base_hosts, hosts_path);
                        // Resolve the TUN ifindex so the responder can
                        // drop queries arriving on the mesh interface
                        // Without this, the `::` bind exposes the
                        // hosts file's alias space to any mesh peer.
                        // The name comes from the device the TUN
                        // path actually created, not the configured
                        // one: macOS and FreeBSD assign utunN/tunN
                        // of their own choosing and the configured
                        // name resolves to nothing there, which left
                        // the filter permanently off.
                        let mesh = self.dns_mesh_side();
                        if self.tun_name.is_some() && mesh.ifindex.is_none() {
                            warn!(
                                device = ?self.tun_name,
                                "Mesh interface index unresolved; DNS mesh filter falls back to {}",
                                DNS_MESH_FALLBACK
                            );
                        }
                        info!(
                            bind = %local_addr,
                            hosts = reloader.hosts().len(),
                            mesh_ifindex = ?mesh.ifindex,
                            "DNS responder started for .fips domain (auto-reload enabled)"
                        );
                        // Self-report on exit so the supervisor FSM
                        // routes health when the DNS task dies at
                        // runtime. The responder never returns, so
                        // in practice that is a panic. On a
                        // deliberate stop the task is `.abort()`ed,
                        // which drops the report with it; even if
                        // one fired, the FSM ignores it outside
                        // `Running`.
                        let handle = tokio::spawn(report_exit(
                            Child::Dns,
                            run_responder(socket, keys, dns_ttl, reloader, Some(aliases_rx), mesh),
                            exit_tx,
                        ));
                        self.dns_task = Some(handle);
                        self.dns_aliases = Some(aliases_tx);
                        self.dns_local_addr = Some(local_addr);
                        true
                    }
                    Err(e) => {
                        warn!(bind = %bind, error = %e, "Failed to start DNS responder");
                        false
                    }
                }
            }
            Err(e) => {
                warn!(addr = %addr_str, error = %e, "Invalid dns.bind_addr; DNS responder not started");
                false
            }
        }
    }

    /// Give the running DNS responder a new peer-alias base, which it applies
    /// before answering its next query. Does nothing while it is not running.
    pub(crate) fn publish_aliases(&self, base: HostMap) {
        if let Some(tx) = &self.dns_aliases {
            tx.send_replace(base);
        }
    }

    /// Stop the DNS responder and retract its published address.
    pub(crate) fn stop_dns(&mut self) {
        // Stop DNS responder
        if let Some(handle) = self.dns_task.take() {
            handle.abort();
            debug!("DNS responder stopped");
        }
        self.dns_aliases.take();
        // Retract the published address in the same step that kills
        // the listener, so an embedder polling `dns_local_addr()`
        // never dials a socket that is already gone.
        self.dns_local_addr.take();
    }
}

/// Where the DNS responder puts a key it hands to the host: into the
/// adapter's own map, so the host's first packet to it is forwarded, and to
/// the node, which registers it.
pub(crate) struct Learner {
    /// The adapter's state, holding its map.
    pub(crate) state: MeshState,
    /// The node's end of the link.
    pub(crate) learned: Sender<Learned>,
    /// Whether to record keys in the map: only while the node feeds it,
    /// since only then does the node say what to forget.
    pub(crate) keep: bool,
}

impl Learner {
    /// Record `peer` in our map, if we keep one, and report it to the node,
    /// waiting for room on the link.
    pub(crate) async fn learn(&self, peer: super::link::PeerKey) {
        let report = if self.keep {
            self.state.learn(peer)
        } else {
            self.state.report(peer)
        };
        let _ = self.learned.send(report).await;
    }
}
