//! FIPS daemon binary
//!
//! Loads configuration and creates the top-level node instance.

use clap::Parser;
use fips::config::{resolve_identity, IdentitySource};
use fips::version;
use fips::{Config, Node};
use std::path::PathBuf;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

/// FIPS mesh network daemon
#[derive(Parser, Debug)]
#[command(
    name = "fips",
    version = version::short_version(),
    long_version = version::long_version(),
    about
)]
struct Args {
    /// Path to configuration file (overrides default search paths)
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();

    // Load configuration before initializing logging so we can use
    // the config's log_level as the tracing filter default.
    let (config, loaded_paths) = if let Some(config_path) = &args.config {
        match Config::load_file(config_path) {
            Ok(config) => (config, vec![config_path.clone()]),
            Err(e) => {
                eprintln!("Failed to load configuration from {}: {}", config_path.display(), e);
                std::process::exit(1);
            }
        }
    } else {
        match Config::load() {
            Ok(result) => result,
            Err(e) => {
                eprintln!("Failed to load configuration: {}", e);
                std::process::exit(1);
            }
        }
    };

    // Initialize logging: RUST_LOG env var overrides config if set
    let log_level = config.node.log_level();
    let filter = EnvFilter::builder()
        .with_default_directive(log_level.into())
        .from_env_lossy();

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    info!("FIPS {} starting", version::short_version());

    if loaded_paths.is_empty() {
        info!("No config files found, using defaults");
    } else {
        for path in &loaded_paths {
            info!(path = %path.display(), "Loaded config file");
        }
    }

    // Identity provisioning: config nsec > key file > generate ephemeral
    let resolved = match resolve_identity(&config, &loaded_paths) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to resolve identity: {}", e);
            std::process::exit(1);
        }
    };
    match &resolved.source {
        IdentitySource::Config => info!("Using identity from configuration"),
        IdentitySource::KeyFile(p) => info!(path = %p.display(), "Loaded persistent identity from key file"),
        IdentitySource::Generated(p) => info!(path = %p.display(), "Generated persistent identity, saved to key file"),
        IdentitySource::Ephemeral => info!("Using ephemeral identity (new keypair each start)"),
    }

    // Create node with resolved identity
    let mut config = config;
    config.node.identity.nsec = Some(resolved.nsec);
    debug!("Creating node");
    let mut node = match Node::new(config) {
        Ok(node) => node,
        Err(e) => {
            error!("Failed to create node: {}", e);
            std::process::exit(1);
        }
    };

    // Log node information
    info!("Node created:");
    info!("      npub: {}", node.npub());
    info!("   node_addr: {}", hex::encode(node.node_addr().as_bytes()));
    info!("   address: {}", node.identity().address());
    info!("     state: {}", node.state());
    info!(" leaf_only: {}", node.is_leaf_only());

    // Start the node (initializes TUN, spawns I/O threads)
    if let Err(e) = node.start().await {
        error!("Failed to start node: {}", e);
        std::process::exit(1);
    }

    info!("FIPS running, press Ctrl+C to exit");

    // Run the RX event loop until shutdown signal (SIGINT or SIGTERM).
    // stop() drops the packet channel, causing run_rx_loop to exit.
    #[cfg(unix)]
    let shutdown = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    };
    #[cfg(not(unix))]
    let shutdown = tokio::signal::ctrl_c();

    tokio::select! {
        result = node.run_rx_loop() => {
            match result {
                Ok(()) => info!("RX loop exited"),
                Err(e) => error!("RX loop error: {}", e),
            }
        }
        _ = shutdown => {
            info!("Shutdown signal received");
        }
    }

    info!("FIPS shutting down");

    // Stop the node (shuts down transports, TUN, I/O threads)
    if let Err(e) = node.stop().await {
        warn!("Error during shutdown: {}", e);
    }

    info!("FIPS shutdown complete");
}
