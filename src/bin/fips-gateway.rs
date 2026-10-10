//! FIPS outbound LAN gateway binary.
//!
//! Allows unmodified LAN hosts to reach FIPS mesh destinations via
//! DNS-allocated virtual IPs and kernel nftables NAT.

#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use fips::Config;
#[cfg(target_os = "linux")]
use fips::gateway::{control, dns, nat, net, pool, state};
#[cfg(target_os = "linux")]
use fips::version;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
#[cfg(target_os = "linux")]
use std::time::Instant;
#[cfg(target_os = "linux")]
use tokio::signal::unix::{SignalKind, signal};
#[cfg(target_os = "linux")]
use tokio::sync::{Mutex, mpsc, watch};
#[cfg(target_os = "linux")]
use tracing::{debug, error, info, warn};
#[cfg(target_os = "linux")]
use tracing_subscriber::{EnvFilter, fmt};

/// FIPS outbound LAN gateway
#[cfg(target_os = "linux")]
#[derive(Parser, Debug)]
#[command(
    name = "fips-gateway",
    version = version::short_version(),
    long_version = version::long_version(),
    about
)]
struct Args {
    /// Path to configuration file (overrides default search paths).
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("fips-gateway requires Linux (nftables unavailable on this platform)");
    std::process::exit(1);
}

/// Microseconds since `started`, saturating, for the timing fields on debug
/// lines.
#[cfg(target_os = "linux")]
fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Take a conntrack snapshot off the runtime thread.
///
/// A failed read yields an empty snapshot, so every mapping reads zero
/// sessions, which is what the pool did with an unreadable source before. The
/// alternative, treating "unknown" as "in use", would pin every mapping forever
/// on a kernel with no readable conntrack source and turn a read error into a
/// pool that never reclaims. The cost is the opposite error: a mapping carrying
/// live traffic can be reclaimed early while the source is unreadable.
#[cfg(target_os = "linux")]
async fn read_conntrack(log: &mut pool::ConntrackReadLog) -> pool::ConntrackSnapshot {
    use fips::gateway::pool::ConntrackQuerier;

    match tokio::task::spawn_blocking(|| pool::SystemConntrack::default().snapshot()).await {
        Ok(Ok(snapshot)) => {
            log.observe(None);
            snapshot
        }
        Ok(Err(e)) => {
            report_unreadable_conntrack(log, e.kind(), &e.to_string());
            pool::ConntrackSnapshot::default()
        }
        Err(e) => {
            report_unreadable_conntrack(log, std::io::ErrorKind::Other, &e.to_string());
            pool::ConntrackSnapshot::default()
        }
    }
}

/// Log an unreadable conntrack source once per change of outcome.
#[cfg(target_os = "linux")]
fn report_unreadable_conntrack(
    log: &mut pool::ConntrackReadLog,
    kind: std::io::ErrorKind,
    error: &str,
) {
    match log.observe(Some(kind)) {
        pool::ReadReport::Changed => warn!(
            error,
            "Conntrack unreadable; every mapping reads zero sessions"
        ),
        pool::ReadReport::Repeated => debug!(
            error,
            "Conntrack still unreadable; every mapping reads zero sessions"
        ),
    }
}

/// Say what the start found of the previous run's pool state.
#[cfg(target_os = "linux")]
fn report_loaded_state(loaded: &state::Loaded) {
    match loaded {
        state::Loaded::Absent => {
            info!("No pool state found; the pool starts at a random address")
        }
        state::Loaded::Invalid(reason) => warn!(
            reason = %reason,
            "Pool state unusable; the pool starts at a random address"
        ),
        state::Loaded::Restored(restored) => info!(
            from = restored.from,
            stretch = restored.span,
            held = restored
                .held
                .iter()
                .map(|[a, b]| u64::from(b - a) + 1)
                .sum::<u64>(),
            hold_secs = restored.hold_secs,
            "Pool state restored; holding the previous run's addresses"
        ),
    }
}

/// Write the pool state on a blocking thread.
#[cfg(target_os = "linux")]
async fn save_pool_state(request: pool::PoolState) -> std::io::Result<()> {
    tokio::task::spawn_blocking(move || {
        state::save(Path::new(state::STATE_DIR), &request, state::is_tmpfs)
    })
    .await
    .unwrap_or_else(|e| Err(std::io::Error::other(e)))
}

/// Check once at startup which conntrack source the tick will read, and say so.
///
/// Without this, an operator on a kernel with no readable source learns that
/// session pinning is off only from a warning at the first failed tick.
#[cfg(target_os = "linux")]
async fn report_conntrack_source() {
    let probe =
        tokio::task::spawn_blocking(|| pool::probe_conntrack(&pool::SystemConntrack::default()))
            .await
            .unwrap_or_else(|e| {
                pool::ConntrackProbe::Missing(pool::ConntrackUnreadable {
                    proc: std::io::Error::other(e.to_string()),
                    netlink: None,
                })
            });
    match probe {
        pool::ConntrackProbe::Found(pool::ConntrackSource::Proc) => {
            info!("Conntrack source: proc; session pinning is on")
        }
        pool::ConntrackProbe::Found(pool::ConntrackSource::Netlink) => {
            info!("Conntrack source: netlink; session pinning is on")
        }
        pool::ConntrackProbe::Missing(e) => match e.netlink {
            Some(netlink) => warn!(
                proc_error = %e.proc,
                netlink_error = %netlink,
                "No conntrack source is readable; session pinning is off"
            ),
            None => warn!(
                proc_error = %e.proc,
                "No conntrack source is readable; session pinning is off"
            ),
        },
    }
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Register the stop signals before set-up. Until a handler exists a
    // SIGTERM takes the default action, which as PID 1 in a container means
    // the kernel discards it; registered here, a stop during set-up is held.
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");

    let args = Args::parse();

    // Initialize logging
    let filter = EnvFilter::builder()
        .with_default_directive(
            args.log_level
                .parse()
                .unwrap_or_else(|_| tracing::level_filters::LevelFilter::INFO.into()),
        )
        .from_env_lossy();

    // As in the daemon: a failed log write must not panic whoever logged. The
    // default reports write failures with `eprintln!`, which panics when stderr
    // fails too, and both units send stdout and stderr to journald. Here the
    // casualty is a spawned task — the DNS resolver or the pool tick — whose
    // handle nothing observes until shutdown.
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .log_internal_errors(false)
        .init();

    info!("fips-gateway {} starting", version::short_version());

    // Load configuration
    let config = if let Some(config_path) = &args.config {
        match Config::load_file(config_path) {
            Ok(config) => {
                info!(path = %config_path.display(), "Loaded config file");
                config
            }
            Err(e) => {
                error!(
                    "Failed to load config from {}: {}",
                    config_path.display(),
                    e
                );
                std::process::exit(1);
            }
        }
    } else {
        match Config::load() {
            Ok((config, paths)) => {
                if paths.is_empty() {
                    warn!("No config files found, using defaults");
                } else {
                    for path in &paths {
                        info!(path = %path.display(), "Loaded config file");
                    }
                }
                config
            }
            Err(e) => {
                error!("Failed to load config: {}", e);
                std::process::exit(1);
            }
        }
    };

    // Validate gateway config
    let gw_config = match &config.gateway {
        Some(gw) if gw.enabled => gw.clone(),
        Some(_) => {
            error!("Gateway section exists but is not enabled (gateway.enabled = false)");
            std::process::exit(1);
        }
        None => {
            error!("No gateway section in configuration");
            std::process::exit(1);
        }
    };

    if let Err(e) = gw_config.validate_port_forwards() {
        error!("Invalid gateway.port_forwards: {e}");
        std::process::exit(1);
    }

    info!(
        pool = %gw_config.pool,
        lan_interface = %gw_config.lan_interface,
        port_forwards = gw_config.port_forwards.len(),
        "Gateway config loaded"
    );

    // --- Prerequisites ---

    // Check IPv6 forwarding
    net::check_ipv6_forwarding();

    // Check fips0 interface exists
    if let Err(e) = net::check_interface_exists("fips0").await {
        error!(error = %e, "fips0 interface not found — is the FIPS daemon running?");
        std::process::exit(1);
    }

    // Check LAN interface exists
    if let Err(e) = net::check_interface_exists(&gw_config.lan_interface).await {
        error!(
            error = %e,
            interface = %gw_config.lan_interface,
            "LAN interface not found"
        );
        std::process::exit(1);
    }

    // Check DNS upstream reachability (proves the FIPS daemon is running).
    // The resolver later forwards to the address this probe reached.
    let upstream_addr = {
        let upstream = gw_config.dns.upstream();
        info!(upstream = %upstream, "Checking DNS upstream reachability");

        use std::net::ToSocketAddrs;
        let upstream_addr = match upstream.to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => addr,
                None => {
                    error!(upstream = %upstream, "DNS upstream address resolved to nothing");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                error!(upstream = %upstream, error = %e, "Invalid DNS upstream address");
                std::process::exit(1);
            }
        };

        // Build a minimal DNS query for "test.fips" AAAA
        // Header: ID=0x1234, flags=0x0100 (standard query, RD=1),
        //   QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        // Question: 4test4fips0 QTYPE=AAAA(28) QCLASS=IN(1)
        let query: Vec<u8> = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: standard query, RD=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // QNAME: "test.fips"
            0x04, b't', b'e', b's', b't', 0x04, b'f', b'i', b'p', b's', 0x00, 0x00,
            0x1C, // QTYPE = AAAA (28)
            0x00, 0x01, // QCLASS = IN (1)
        ];

        let bind_addr = if upstream_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = match tokio::net::UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "Failed to bind UDP socket for DNS check");
                std::process::exit(1);
            }
        };

        // Retry the upstream probe up to MAX_PROBE_ATTEMPTS times with a
        // 1-second per-attempt timeout and a 1-second sleep between
        // attempts. Total worst-case wait: ~10 seconds.
        //
        // Bounded retry covers the cold-boot race where this gateway and
        // the fips daemon start at approximately the same time: the
        // daemon's TUN may be up (the systemd ExecStartPre wait already
        // gates on that) while its DNS responder is still binding
        // [::1]:5354. Without this retry, the gateway hard-failed after
        // a single 3-second probe and relied on Restart=on-failure for
        // recovery.
        const MAX_PROBE_ATTEMPTS: u32 = 5;
        const PROBE_TIMEOUT_SECS: u64 = 1;
        const PROBE_RETRY_DELAY_SECS: u64 = 1;

        let mut buf = [0u8; 512];
        let mut last_failure: Option<String> = None;
        let probe = async {
            for attempt in 1..=MAX_PROBE_ATTEMPTS {
                if let Err(e) = sock.send_to(&query, upstream_addr).await {
                    last_failure = Some(format!("send_to failed: {}", e));
                } else {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(PROBE_TIMEOUT_SECS),
                        sock.recv_from(&mut buf),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            info!(
                                upstream = %upstream, attempt = attempt,
                                "DNS upstream is reachable"
                            );
                            return true;
                        }
                        Ok(Err(e)) => {
                            last_failure = Some(format!("recv_from failed: {}", e));
                        }
                        Err(_) => {
                            last_failure =
                                Some(format!("no response within {}s", PROBE_TIMEOUT_SECS));
                        }
                    }
                }
                if attempt < MAX_PROBE_ATTEMPTS {
                    info!(
                        upstream = %upstream, attempt = attempt,
                        last = ?last_failure,
                        "DNS upstream probe attempt failed; retrying"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(PROBE_RETRY_DELAY_SECS))
                        .await;
                }
            }
            false
        };
        // A stop during the probe ends it at once. Nothing that needs
        // tearing down exists yet: the probe socket is the only resource.
        let succeeded = tokio::select! {
            biased;
            _ = sigterm.recv() => {
                info!("Received SIGTERM during start-up, exiting");
                std::process::exit(0);
            }
            _ = sigint.recv() => {
                info!("Received SIGINT during start-up, exiting");
                std::process::exit(0);
            }
            succeeded = probe => succeeded,
        };
        if !succeeded {
            error!(
                upstream = %upstream,
                attempts = MAX_PROBE_ATTEMPTS,
                last = ?last_failure,
                "DNS upstream did not become reachable after exhausting retries — is the FIPS daemon running?"
            );
            std::process::exit(1);
        }
        upstream_addr
    };

    // --- Bind the DNS listener ---
    //
    // Before the pool, NAT table and routes exist, so a port that is already
    // taken ends the gateway with nothing to tear down, and a service manager
    // restarting it does not churn nftables.
    if gw_config.dns.is_mdns() {
        warn!(
            "gateway.dns.listen uses port 5353, the mDNS port; an mDNS responder (the fips daemon's LAN rendezvous, avahi) will conflict with it; the default is now [::1]:5365"
        );
    }
    let dns_socket = match dns::bind_listener(gw_config.dns.listen()).await {
        Ok(socket) => socket,
        Err(e) => {
            error!("{e}");
            std::process::exit(1);
        }
    };
    match dns_socket.local_addr() {
        Ok(addr) => info!(addr = %addr, "Gateway DNS resolver listening"),
        Err(_) => info!(addr = %gw_config.dns.listen(), "Gateway DNS resolver listening"),
    }

    // --- Initialize components ---

    // Virtual IP pool, started from the previous run's state when there is
    // one, so no address a client may still hold an answer for is reissued.
    let pool_total = match pool::pool_total(&gw_config.pool) {
        Ok(total) => total,
        Err(e) => {
            error!(error = %e, "Failed to create virtual IP pool");
            std::process::exit(1);
        }
    };
    // A restored pool's holds are written back before the steps that can
    // end the start, since loading removed the file.
    let mut save_log = state::SaveLog::default();
    let ip_pool = match state::start_pool(
        Path::new(state::STATE_DIR),
        &gw_config.pool,
        pool_total,
        gw_config.dns.ttl() as u64,
        gw_config.grace_period(),
        rand::random::<u32>() % pool_total + 1,
        Instant::now(),
        state::is_tmpfs,
    ) {
        Ok(started) => {
            report_loaded_state(&started.loaded);
            if let Some(result) = &started.carried {
                save_log.report(result);
            }
            started.pool
        }
        Err(e) => {
            error!(error = %e, "Failed to create virtual IP pool");
            std::process::exit(1);
        }
    };
    let pool_network = ip_pool.network();

    let ip_pool = Arc::new(Mutex::new(ip_pool));

    // NAT manager
    let mut nat_mgr = match nat::NatManager::new(gw_config.lan_interface.clone(), pool_network) {
        Ok(n) => n,
        Err(e) => {
            error!(error = %e, "Failed to create nftables table — do you have CAP_NET_ADMIN?");
            std::process::exit(1);
        }
    };

    // Install inbound port-forward rules.
    if let Err(e) = nat_mgr.set_port_forwards(&gw_config.port_forwards) {
        error!(error = %e, "Failed to install port-forward rules");
        let _ = nat_mgr.cleanup();
        std::process::exit(1);
    }

    // Network setup
    let mut net_setup = net::NetSetup::new(gw_config.lan_interface.clone(), gw_config.pool.clone());

    // Add pool route
    if let Err(e) = net_setup.add_pool_route().await {
        error!(error = %e, "Failed to add pool route");
        // Clean up NAT table before exit
        let _ = nat_mgr.cleanup();
        std::process::exit(1);
    }

    // The NAT table exists by now, so a kernel that provides the proc file
    // has loaded nf_conntrack and the probe sees what the first tick will.
    report_conntrack_source().await;

    // Write the state that covers the first addresses before any is issued.
    // This is the first write with a stretch, made after the last step that
    // can end the start, so a start that fails earlier leaves no stretch for
    // the next one to hold; later writes run off the runtime thread.
    {
        let mut pool_guard = ip_pool.lock().await;
        if let Some(request) = pool_guard.mark_request() {
            let result = state::save(Path::new(state::STATE_DIR), &request, state::is_tmpfs);
            save_log.report(&result);
            match result {
                Ok(()) => pool_guard.confirm_mark(&request),
                Err(_) => pool_guard.mark_failed(),
            }
        }
    }

    // Nothing reads the reports yet, so they are dropped here.
    let (mut nat_driver, _) = nat::NatDriver::start(Box::new(nat_mgr));

    // --- Channels ---

    // Pool events (new/removed mappings) → NAT + net modules
    let (event_tx, mut event_rx) = mpsc::channel::<pool::PoolEvent>(64);

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // --- Start DNS resolver task ---

    // Held in an Option because the main loop may see it complete, and a
    // completed JoinHandle panics if it is polled again.
    let mut dns_task = Some(tokio::spawn(dns::serve(
        dns_socket,
        upstream_addr,
        gw_config.dns.ttl(),
        Arc::clone(&ip_pool),
        event_tx.clone(),
        shutdown_rx.clone(),
    )));

    // --- Snapshot channel for control socket ---

    let (snapshot_tx, snapshot_rx) = watch::channel::<Option<control::GatewaySnapshot>>(None);
    let start_time = Instant::now();

    // --- Start control socket ---

    let control_task = match control::GatewayControlSocket::bind() {
        Ok(socket) => {
            let rx = snapshot_rx.clone();
            Some(tokio::spawn(async move {
                socket.accept_loop(rx).await;
            }))
        }
        Err(e) => {
            warn!(error = %e, "Failed to bind gateway control socket — continuing without it");
            None
        }
    };

    // --- NAT mapping counter (shared with tick task for snapshots) ---

    let nat_count = nat_driver.mapping_counter();

    // --- Start pool tick task ---

    let tick_pool = Arc::clone(&ip_pool);
    let tick_event_tx = event_tx;
    let tick_nat_count = Arc::clone(&nat_count);
    let mut tick_shutdown = shutdown_rx.clone();
    let mut conntrack_log = pool::ConntrackReadLog::default();
    let snap_config = control::SnapshotConfig {
        pool_cidr: gw_config.pool.clone(),
        lan_interface: gw_config.lan_interface.clone(),
        dns_upstream: gw_config.dns.upstream().to_string(),
        dns_listen: gw_config.dns.listen().to_string(),
        dns_ttl: gw_config.dns.ttl(),
        pool_grace_period: gw_config.grace_period(),
    };

    let tick_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        let mut save_log = save_log;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = Instant::now();
                    // Read conntrack once, off the runtime thread and before
                    // the pool lock: the runtime is current-thread, so a
                    // blocking read here would stall the DNS resolver, and the
                    // read must not happen under the lock the resolver needs.
                    let read_started = Instant::now();
                    let conntrack = read_conntrack(&mut conntrack_log).await;
                    let read_us = elapsed_us(read_started);
                    let mut pool_guard = tick_pool.lock().await;
                    let tick_started = Instant::now();
                    let events = pool_guard.tick(now, &conntrack);
                    let tick_us = elapsed_us(tick_started);

                    // Build snapshot for control socket
                    let pool_status = pool_guard.status();
                    let mappings = pool_guard.mapping_info(now);
                    let request = pool_guard.mark_request();
                    drop(pool_guard);
                    debug!(mappings = mappings.len(), read_us, tick_us, "Pool tick");

                    // Write the pool state off the runtime thread and without
                    // the pool lock; names issued meanwhile fall in the stretch
                    // the previous write already covers.
                    if let Some(request) = request {
                        let result = save_pool_state(request.clone()).await;
                        save_log.report(&result);
                        let mut pool_guard = tick_pool.lock().await;
                        match result {
                            Ok(()) => pool_guard.confirm_mark(&request),
                            Err(_) => pool_guard.mark_failed(),
                        }
                    }

                    let snapshot = control::build_snapshot(
                        pool_status,
                        mappings,
                        tick_nat_count.load(Ordering::Relaxed),
                        start_time,
                        &snap_config,
                    );
                    let _ = snapshot_tx.send(Some(snapshot));

                    for event in events {
                        let _ = tick_event_tx.send(event).await;
                    }
                }
                _ = tick_shutdown.changed() => break,
            }
        }
        save_log
    });

    // --- Event processing loop ---

    info!("fips-gateway running");

    let mut exit_code = 0;
    let mut nat_retry = tokio::time::interval(std::time::Duration::from_secs(10));
    nat_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = nat_retry.tick() => {
                nat_driver.retry();
            }
            Some(event) = event_rx.recv() => {
                match event {
                    pool::PoolEvent::MappingCreated { virtual_ip, mesh_addr } => {
                        // Add NAT rules
                        let _ = nat_driver.submit(nat::NatCommand::Add { virtual_ip, mesh_addr });
                        // Add proxy NDP entry
                        if let Err(e) = net_setup.add_proxy_ndp(virtual_ip).await {
                            error!(error = %e, virtual_ip = %virtual_ip, "Failed to add proxy NDP");
                        }
                    }
                    pool::PoolEvent::MappingRemoved { virtual_ip, mesh_addr } => {
                        // Remove NAT rules
                        let _ = nat_driver.submit(nat::NatCommand::Remove { virtual_ip, mesh_addr });
                        // Remove proxy NDP entry
                        if let Err(e) = net_setup.remove_proxy_ndp(virtual_ip).await {
                            warn!(error = %e, virtual_ip = %virtual_ip, "Failed to remove proxy NDP");
                        }
                    }
                }
            }
            // The resolver ends only on shutdown, which has not been
            // signalled while this loop runs, so any completion here means
            // .fips resolution has stopped. Exit non-zero so systemd or procd
            // restarts the gateway or shows it failed.
            result = async { dns_task.as_mut().expect("guarded by the precondition").await },
                if dns_task.is_some() => {
                dns_task = None;
                let cause = match result {
                    Ok(Ok(())) => "the resolver returned without an error".to_string(),
                    Ok(Err(e)) => e.to_string(),
                    Err(e) => e.to_string(),
                };
                error!(
                    cause = %cause,
                    "Gateway DNS resolver stopped; exiting so the service manager restarts the gateway"
                );
                exit_code = 1;
                break;
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down");
                break;
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down");
                break;
            }
        }
    }

    // --- Shutdown ---

    info!("fips-gateway shutting down");

    // Signal all tasks to stop
    let _ = shutdown_tx.send(true);

    // Wait for tasks (control task is cancelled by dropping the listener)
    if let Some(task) = control_task {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = dns_task {
        let _ = task.await;
    }
    let mut save_log = tick_task.await.unwrap_or_default();

    // Log final pool status, and write the exact set of addresses a client
    // may still hold an answer for: nothing is issued any more, so the next
    // start holds only these and resolves new names at once.
    let final_state = {
        let pool_guard = ip_pool.lock().await;
        let status = pool_guard.status();
        info!(
            total = status.total,
            allocated = status.allocated,
            active = status.active,
            draining = status.draining,
            free = status.free,
            "Final pool status"
        );
        pool_guard.shutdown_state()
    };
    save_log.report(&save_pool_state(final_state).await);

    // Clean up network and NAT
    net_setup.cleanup().await;
    if let Err(e) = nat_driver.shutdown(nat::NAT_STOP_TIMEOUT) {
        warn!(error = %e, "Failed to clean up nftables table");
    }

    info!("fips-gateway shutdown complete");
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}
