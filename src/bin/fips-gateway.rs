//! FIPS outbound LAN gateway binary.
//!
//! Allows unmodified LAN hosts to reach FIPS mesh destinations via
//! DNS-allocated virtual IPs and kernel nftables NAT.

use clap::Parser;
use fips::Config;
#[cfg(target_os = "linux")]
use fips::gateway::{control, dns, nat, net, pool};
use fips::version;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Mutex, mpsc, watch};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt};

/// FIPS outbound LAN gateway
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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();

    // Initialize logging
    let filter = EnvFilter::builder()
        .with_default_directive(
            args.log_level
                .parse()
                .unwrap_or_else(|_| tracing::level_filters::LevelFilter::INFO.into()),
        )
        .from_env_lossy();

    fmt().with_env_filter(filter).with_target(true).init();

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

    // Check DNS upstream reachability (proves the FIPS daemon is running)
    {
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

        if let Err(e) = sock.send_to(&query, upstream_addr).await {
            error!(
                upstream = %upstream, error = %e,
                "Failed to send DNS probe — is the FIPS daemon running?"
            );
            std::process::exit(1);
        }

        let mut buf = [0u8; 512];
        match tokio::time::timeout(std::time::Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
        {
            Ok(Ok(_)) => {
                info!(upstream = %upstream, "DNS upstream is reachable");
            }
            Ok(Err(e)) => {
                error!(
                    upstream = %upstream, error = %e,
                    "DNS upstream recv failed — is the FIPS daemon running?"
                );
                std::process::exit(1);
            }
            Err(_) => {
                error!(
                    upstream = %upstream,
                    "DNS upstream did not respond within 3s — is the FIPS daemon running?"
                );
                std::process::exit(1);
            }
        }
    }

    // --- Initialize components ---

    // Virtual IP pool
    let ip_pool = match pool::VirtualIpPool::new(
        &gw_config.pool,
        gw_config.dns.ttl() as u64,
        gw_config.grace_period(),
    ) {
        Ok(p) => Arc::new(Mutex::new(p)),
        Err(e) => {
            error!(error = %e, "Failed to create virtual IP pool");
            std::process::exit(1);
        }
    };

    // NAT manager
    let mut nat_mgr = match nat::NatManager::new(gw_config.lan_interface.clone()) {
        Ok(n) => n,
        Err(e) => {
            error!(error = %e, "Failed to create nftables table — do you have CAP_NET_ADMIN?");
            std::process::exit(1);
        }
    };

    // Install inbound port-forward rules (TASK-2026-0061).
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

    // --- Channels ---

    // Pool events (new/removed mappings) → NAT + net modules
    let (event_tx, mut event_rx) = mpsc::channel::<pool::PoolEvent>(64);

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // --- Start DNS resolver task ---

    let dns_pool = Arc::clone(&ip_pool);
    let dns_event_tx = event_tx.clone();
    let dns_shutdown = shutdown_rx.clone();
    let dns_listen = gw_config.dns.listen().to_string();
    let dns_upstream = gw_config.dns.upstream().to_string();
    let dns_ttl = gw_config.dns.ttl();

    let dns_task = tokio::spawn(async move {
        if let Err(e) = dns::run_dns_resolver(
            &dns_listen,
            &dns_upstream,
            dns_ttl,
            dns_pool,
            dns_event_tx,
            dns_shutdown,
        )
        .await
        {
            error!(error = %e, "DNS resolver error");
        }
    });

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

    let nat_count = Arc::new(AtomicUsize::new(0));

    // --- Start pool tick task ---

    let tick_pool = Arc::clone(&ip_pool);
    let tick_event_tx = event_tx;
    let tick_nat_count = Arc::clone(&nat_count);
    let mut tick_shutdown = shutdown_rx.clone();
    let conntrack = pool::ProcConntrack;
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
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = Instant::now();
                    let mut pool_guard = tick_pool.lock().await;
                    let events = pool_guard.tick(now, &conntrack);

                    // Build snapshot for control socket
                    let pool_status = pool_guard.status();
                    let mappings = pool_guard.mapping_info(now);
                    drop(pool_guard);

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
    });

    // --- Event processing loop ---

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");

    info!("fips-gateway running");

    loop {
        tokio::select! {
            Some(event) = event_rx.recv() => {
                match event {
                    pool::PoolEvent::MappingCreated { virtual_ip, mesh_addr } => {
                        // Add NAT rules
                        if let Err(e) = nat_mgr.add_mapping(virtual_ip, mesh_addr) {
                            error!(error = %e, virtual_ip = %virtual_ip, "Failed to add NAT rules");
                        }
                        nat_count.store(nat_mgr.mapping_count(), Ordering::Relaxed);
                        // Add proxy NDP entry
                        if let Err(e) = net_setup.add_proxy_ndp(virtual_ip).await {
                            error!(error = %e, virtual_ip = %virtual_ip, "Failed to add proxy NDP");
                        }
                    }
                    pool::PoolEvent::MappingRemoved { virtual_ip, mesh_addr: _ } => {
                        // Remove NAT rules
                        if let Err(e) = nat_mgr.remove_mapping(virtual_ip) {
                            warn!(error = %e, virtual_ip = %virtual_ip, "Failed to remove NAT rules");
                        }
                        nat_count.store(nat_mgr.mapping_count(), Ordering::Relaxed);
                        // Remove proxy NDP entry
                        if let Err(e) = net_setup.remove_proxy_ndp(virtual_ip).await {
                            warn!(error = %e, virtual_ip = %virtual_ip, "Failed to remove proxy NDP");
                        }
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
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
    let _ = dns_task.await;
    let _ = tick_task.await;

    // Log final pool status
    {
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
    }

    // Clean up network and NAT
    net_setup.cleanup().await;
    if let Err(e) = nat_mgr.cleanup() {
        warn!(error = %e, "Failed to clean up nftables table");
    }

    info!("fips-gateway shutdown complete");
}
