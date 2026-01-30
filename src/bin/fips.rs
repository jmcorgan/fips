//! FIPS daemon binary
//!
//! Loads configuration and creates the top-level node instance.

use fips::{
    build_dest_unreachable, log_ipv6_packet, should_send_icmp_error, shutdown_tun_interface,
    Config, DestUnreachableCode, FipsAddress, Node, TunDevice, TunTx,
};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::{fmt, EnvFilter};

/// TUN packet reader loop.
///
/// Reads packets from the TUN device, logs them, and sends ICMPv6
/// Destination Unreachable responses for packets we can't route.
///
/// This runs in a separate thread since TUN reads are blocking.
fn run_tun_reader(mut device: TunDevice, mtu: u16, our_addr: FipsAddress, tun_tx: TunTx) {
    let mut buf = vec![0u8; mtu as usize + 100]; // Extra space for headers

    loop {
        match device.read_packet(&mut buf) {
            Ok(n) if n > 0 => {
                let packet = &buf[..n];
                log_ipv6_packet(packet);

                // Currently no routing capability - send ICMPv6 Destination Unreachable
                // for all packets that qualify for an error response
                if should_send_icmp_error(packet) {
                    if let Some(response) = build_dest_unreachable(
                        packet,
                        DestUnreachableCode::NoRoute,
                        our_addr.to_ipv6(),
                    ) {
                        debug!(
                            len = response.len(),
                            "Sending ICMPv6 Destination Unreachable"
                        );
                        if tun_tx.send(response).is_err() {
                            info!("TUN writer channel closed, reader stopping");
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
                let err_str = e.to_string();
                if err_str.contains("Bad address") {
                    info!("TUN interface deleted, reader stopping");
                } else {
                    error!("TUN read error: {}", e);
                }
                break;
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Initialize logging
    let filter = EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    info!("FIPS starting");

    // Load configuration
    info!("Loading configuration");
    let (config, loaded_paths) = match Config::load() {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    if loaded_paths.is_empty() {
        info!("No config files found, using defaults");
    } else {
        for path in &loaded_paths {
            info!(path = %path.display(), "Loaded config file");
        }
    }

    // Log identity status
    if config.has_identity() {
        info!("Using configured identity");
    } else {
        warn!("No identity configured, generating ephemeral keypair");
    }

    // Create node
    info!("Creating node");
    let mut node = match Node::new(config) {
        Ok(node) => node,
        Err(e) => {
            error!("Failed to create node: {}", e);
            std::process::exit(1);
        }
    };

    // Log node information
    info!(
        state = %node.state(),
        leaf_only = node.is_leaf_only(),
        "Node created"
    );
    info!("  npub: {}", node.npub());
    info!("  node_id: {}", hex::encode(node.node_id().as_bytes()));
    info!("  address: {}", node.identity().address());

    // Initialize TUN interface
    info!(
        tun_state = %node.tun_state(),
        "TUN interface"
    );

    if node.tun_state() != fips::TunState::Disabled {
        info!(
            name = node.config().tun.name(),
            mtu = node.config().tun.mtu(),
            "Initializing TUN device"
        );

        match node.init_tun().await {
            Ok(true) => {
                let device = node.tun_device().unwrap();
                info!(
                    name = device.name(),
                    mtu = device.mtu(),
                    address = %device.address(),
                    "TUN device active"
                );

                // Show interface details for debugging
                let output = std::process::Command::new("ip")
                    .args(["link", "show", device.name()])
                    .output();
                match output {
                    Ok(out) => {
                        if out.status.success() {
                            info!(
                                "ip link show {}:\n{}",
                                device.name(),
                                String::from_utf8_lossy(&out.stdout)
                            );
                        }
                    }
                    Err(e) => {
                        warn!("Failed to run ip link: {}", e);
                    }
                }
            }
            Ok(false) => {
                info!("TUN disabled");
            }
            Err(e) => {
                error!("Failed to initialize TUN: {}", e);
                warn!("Continuing without TUN interface");
            }
        }
    }

    info!("FIPS initialized successfully");

    // Spawn TUN reader and writer threads if TUN is active
    let tun_name = if let Some(tun_device) = node.take_tun_device() {
        let mtu = tun_device.mtu();
        let name = tun_device.name().to_string();
        let our_addr = *tun_device.address();

        // Create writer (dups the fd for independent write access)
        let (writer, tun_tx) = match tun_device.create_writer() {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to create TUN writer: {}", e);
                std::process::exit(1);
            }
        };

        info!(mtu, name = %name, "Starting TUN reader and writer");

        // Spawn writer thread
        std::thread::spawn(move || {
            writer.run();
        });

        // Spawn reader thread
        std::thread::spawn(move || {
            run_tun_reader(tun_device, mtu, our_addr, tun_tx);
        });

        Some(name)
    } else {
        None
    };

    // TODO: Spawn additional event-driven tasks here:
    // - Transport listeners/senders
    // - Periodic timers (tree announcements, keepalives, etc.)

    info!("FIPS running, press Ctrl+C to exit");

    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("Shutdown signal received"),
        Err(e) => error!("Failed to listen for shutdown signal: {}", e),
    }

    info!("FIPS shutting down");

    // Shutdown TUN interface if active
    if let Some(name) = tun_name {
        info!(name = %name, "Shutting down TUN interface");
        if let Err(e) = shutdown_tun_interface(&name).await {
            warn!("Failed to shutdown TUN interface: {}", e);
        }
    }

    info!("FIPS shutdown complete");
}
