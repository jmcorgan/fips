//! FIPS daemon binary
//!
//! Loads configuration and creates the top-level node instance.

use fips::{Config, Node};
use tracing::{error, info, warn, Level};
use tracing_subscriber::{fmt, EnvFilter};

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

    // TODO: Start event loop, transports, etc.
    info!("No transports configured, nothing to do");
}
