//! FIPS daemon binary
//!
//! Loads configuration and creates the top-level node instance.
//! On Windows, can run as a Windows Service when invoked with `--service`.

use clap::Parser;
use fips::config::{IdentitySource, resolve_identity};
use fips::version;
use fips::{Config, Node};
use std::path::{Path, PathBuf};
use tracing::{debug, error, info};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::{EnvFilter, fmt};
use zeroize::Zeroize;

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

    /// Run as a Windows service (internal use by service control manager)
    #[cfg(windows)]
    #[arg(long, hide = true)]
    service: bool,

    /// Install as a Windows service
    #[cfg(windows)]
    #[arg(long)]
    install_service: bool,

    /// Uninstall the Windows service
    #[cfg(windows)]
    #[arg(long)]
    uninstall_service: bool,
}

/// Where a file-backed log is being written, for the startup log line.
///
/// The operator configured one path and the appender writes another (the
/// rolled name carries the period), so reporting both is what makes the log
/// findable.
struct LogTarget {
    directory: String,
    live_example: String,
}

/// Build the rolling-file writer for `node.log_file`.
///
/// The appender takes a directory plus a prefix and suffix rather than a
/// filename, and interposes the rotation period between them, so
/// `/var/log/fips/fips.log` is written as `fips.2026-08-31.log`. Splitting on
/// the extension rather than appending the date to the whole name is what
/// keeps the `.log` extension on the live file.
///
/// Fatal on failure, matching how this binary treats an unusable config: a
/// daemon that silently discarded its logging because a directory was not
/// writable would present exactly as the disappearing-logs problem the file
/// exists to solve.
fn build_file_writer(
    path: &str,
    config: &fips::Config,
) -> (
    BoxMakeWriter,
    tracing_appender::non_blocking::WorkerGuard,
    LogTarget,
) {
    use fips::config::LogRotation;
    use tracing_appender::rolling::{RollingFileAppender, Rotation};

    let path = Path::new(path);
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        eprintln!("Invalid node.log_file (no filename): {}", path.display());
        std::process::exit(1);
    };
    let extension = path.extension().and_then(|s| s.to_str());

    // The packaged layouts create this, but a hand-written config naming a
    // fresh directory should not have to.
    if let Err(e) = std::fs::create_dir_all(directory) {
        eprintln!("Cannot create log directory {}: {e}", directory.display());
        std::process::exit(1);
    }

    let rotation = match config.node.log_rotation() {
        LogRotation::Hourly => Rotation::HOURLY,
        LogRotation::Daily => Rotation::DAILY,
        LogRotation::Never => Rotation::NEVER,
    };

    let mut builder = RollingFileAppender::builder()
        .rotation(rotation.clone())
        .filename_prefix(stem)
        .max_log_files(config.node.log_max_files());
    if let Some(extension) = extension {
        builder = builder.filename_suffix(extension);
    }

    let appender = match builder.build(directory) {
        Ok(appender) => appender,
        Err(e) => {
            eprintln!("Cannot open log file {}: {e}", path.display());
            std::process::exit(1);
        }
    };

    // Non-blocking: a slow or full disk must not stall the node's tick loop
    // behind a write. The guard returned here keeps the writer thread alive.
    let (writer, guard) = tracing_appender::non_blocking(appender);

    let live_example = match extension {
        Some(extension) => format!("{stem}.<{}>.{extension}", rotation_label(&rotation)),
        None => format!("{stem}.<{}>", rotation_label(&rotation)),
    };

    (
        BoxMakeWriter::new(writer),
        guard,
        LogTarget {
            directory: directory.display().to_string(),
            live_example,
        },
    )
}

/// The shape of the date stamp the appender interposes, for the startup line.
fn rotation_label(rotation: &tracing_appender::rolling::Rotation) -> &'static str {
    use tracing_appender::rolling::Rotation;
    if *rotation == Rotation::HOURLY {
        "YYYY-MM-DD-HH"
    } else if *rotation == Rotation::DAILY {
        "YYYY-MM-DD"
    } else {
        "no date stamp"
    }
}

/// Run the FIPS daemon (shared between foreground and service modes).
///
/// `config_path` overrides the default config search. `shutdown_signal`
/// is awaited to trigger a graceful stop — in foreground mode this is
/// Ctrl+C / SIGTERM, in service mode it's the service stop event.
async fn run_daemon(
    config_path: Option<PathBuf>,
    shutdown_signal: impl std::future::Future<Output = ()>,
) {
    // Load configuration before initializing logging so we can use
    // the config's log_level as the tracing filter default.
    let (config, loaded_paths) = if let Some(config_path) = &config_path {
        match Config::load_file(config_path) {
            Ok(config) => (config, vec![config_path.clone()]),
            Err(e) => {
                eprintln!(
                    "Failed to load configuration from {}: {}",
                    config_path.display(),
                    e
                );
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

    // Initialize logging: RUST_LOG env var overrides config if set.
    //
    // The nostr-sdk relay pool emits the full JSON of every event it
    // sends and receives at DEBUG level. At our DEBUG level that drowns
    // out everything else, so suppress it unless the operator has
    // explicitly asked for TRACE — at which point the raw frames come
    // back.
    let log_level = config.node.log_level();
    let nostr_directive = if log_level == tracing::Level::TRACE {
        "trace"
    } else {
        "info"
    };
    let default_directive = format!(
        "{log_level},nostr_relay_pool={nostr_directive},nostr_sdk={nostr_directive},nostr={nostr_directive}"
    );
    let filter = EnvFilter::builder()
        .with_default_directive(log_level.into())
        .parse_lossy(default_directive);
    let filter = match std::env::var("RUST_LOG") {
        Ok(env) if !env.is_empty() => EnvFilter::builder()
            .with_default_directive(log_level.into())
            .parse_lossy(env),
        _ => filter,
    };

    // Where the log goes. Unset `node.log_file` keeps the stream on stdout
    // for a supervisor to capture, which is what journald and syslog want and
    // what every platform but macOS gets. Naming a file moves ownership of it
    // to us so we can roll it, because launchd holds the descriptor it
    // redirects and gives the daemon no way to reopen one rotated out from
    // under it.
    //
    // `_log_guard` must outlive the daemon: dropping it flushes and stops the
    // writer thread, and a log line emitted after that is discarded. It is
    // held until `main` returns.
    let (writer, _log_guard, log_target) = match config.node.log_file.as_deref() {
        Some(path) => {
            let (writer, guard, target) = build_file_writer(path, &config);
            (writer, Some(guard), Some(target))
        }
        None => (BoxMakeWriter::new(std::io::stdout), None, None),
    };

    // ANSI color only when stdout is a terminal — under a supervisor
    // (daemon(8), systemd) escape codes would litter the log file. A log file
    // we own is never a terminal.
    //
    // Never let a failed log write panic the thread that logged. The default
    // is to report a write failure with `eprintln!`, which itself panics when
    // stderr fails too — and the shipped supervisor configs point stdout and
    // stderr at the same place, so one full disk satisfies both. A worker
    // thread killed that way takes its share of the peer space with it.
    let ansi = log_target.is_none() && std::io::IsTerminal::is_terminal(&std::io::stdout());
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_ansi(ansi)
        .with_writer(writer)
        .log_internal_errors(false)
        .init();

    // Logged first, and only when we own the file: the operator who goes
    // looking for output that is no longer on stdout needs the resolved path
    // and the retention that governs it, and the rolled name is not the one
    // they configured.
    if let Some(target) = &log_target {
        info!(
            directory = %target.directory,
            live_file = %target.live_example,
            rotation = ?config.node.log_rotation(),
            max_files = config.node.log_max_files(),
            "Logging to file"
        );
    }

    info!("FIPS {} starting", version::short_version());

    if loaded_paths.is_empty() {
        info!("No config files found, using defaults");
    } else {
        for path in &loaded_paths {
            info!(path = %path.display(), "Loaded config file");
        }
    }

    // The hosts/ACL defaults on these platforms moved from /etc/fips to
    // /usr/local/etc/fips; flag files stranded at the old location.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    fips::node::warn_on_legacy_config_paths();

    // Identity provisioning: config nsec > key file > generate ephemeral
    let mut resolved = match resolve_identity(&config, &loaded_paths) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to resolve identity: {}", e);
            std::process::exit(1);
        }
    };
    match &resolved.source {
        IdentitySource::Config => info!("Using identity from configuration"),
        IdentitySource::KeyFile(p) => {
            info!(path = %p.display(), "Loaded persistent identity from key file")
        }
        IdentitySource::Generated(p) => {
            info!(path = %p.display(), "Generated persistent identity, saved to key file")
        }
        IdentitySource::Ephemeral => info!("Using ephemeral identity (new keypair each start)"),
    }

    // Create node with resolved identity
    let mut config = config;
    // Take the nsec rather than move it: `ResolvedIdentity` clears its copy
    // on drop, so it cannot be left partially moved. Clear whatever the field
    // already held first — assigning over it drops the old `String` in place,
    // which does not run `Drop for IdentityConfig`, so a key that came from
    // the config file would be freed uncleared.
    if let Some(mut old) = config.node.identity.nsec.take() {
        old.zeroize();
    }
    config.node.identity.nsec = Some(std::mem::take(&mut resolved.nsec));
    debug!("Creating node");
    let mut node = match Node::new(config) {
        Ok(node) => node,
        Err(e) => {
            error!("Failed to create node: {}", e);
            std::process::exit(1);
        }
    };

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

    info!("FIPS running");

    // Serve until the shutdown signal, then drain in place before returning.
    // The rx loop observes the signal directly, so its channels are never
    // destructively cancelled — they live in the loop's locals across serve and
    // drain, and are dropped only on clean exit (after which teardown does not
    // need them). On the signal the loop broadcasts a shutdown Disconnect and
    // waits (bounded by node.drain_timeout_secs) for peers to clear.
    match node.run_rx_loop_with_shutdown(shutdown_signal).await {
        Ok(()) => info!("RX loop exited"),
        Err(e) => error!("RX loop error: {}", e),
    }

    info!("FIPS shutting down");

    // Close the drain window (if the loop drained) and tear down. A drained
    // loop tears down without re-broadcasting; a loop that exited some other
    // way falls back to the immediate stop().
    node.finish_shutdown().await;

    info!("FIPS shutdown complete");
}

/// Build a shutdown future for foreground mode (Ctrl+C / SIGTERM).
async fn foreground_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

// ============================================================================
// Unix entry point
// ============================================================================

#[cfg(not(windows))]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    run_daemon(args.config, foreground_shutdown_signal()).await;
}

// ============================================================================
// Windows entry point and service support
// ============================================================================

#[cfg(windows)]
fn main() {
    let args = Args::parse();

    if args.install_service {
        if let Err(e) = service::install_service() {
            eprintln!("Failed to install service: {}", e);
            std::process::exit(1);
        }
        return;
    }

    if args.uninstall_service {
        if let Err(e) = service::uninstall_service() {
            eprintln!("Failed to uninstall service: {}", e);
            std::process::exit(1);
        }
        return;
    }

    if args.service {
        // Running as a Windows service (invoked by the service control manager)
        if let Err(e) = service::run_as_service() {
            eprintln!("Failed to start as service: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // Foreground mode: build a manual tokio runtime since we can't use
    // #[tokio::main] with platform-conditional main functions.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    rt.block_on(run_daemon(args.config, foreground_shutdown_signal()));
}

#[cfg(windows)]
mod service {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::time::Duration;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
            ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    const SERVICE_NAME: &str = "fips";
    const SERVICE_DISPLAY_NAME: &str = "FIPS Mesh Network Daemon";
    const SERVICE_DESCRIPTION: &str =
        "Free Internetworking Peering System - distributed mesh networking protocol";

    define_windows_service!(ffi_service_main, service_main);

    /// Start the service dispatcher, which blocks until the service stops.
    pub fn run_as_service() -> Result<(), windows_service::Error> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    /// Entry point called by the Windows service control manager.
    fn service_main(arguments: Vec<OsString>) {
        if let Err(e) = run_service(arguments) {
            eprintln!("Service error: {:?}", e);
        }
    }

    /// Core service logic: register control handler, run daemon, report status.
    fn run_service(_arguments: Vec<OsString>) -> Result<(), windows_service::Error> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown_tx = std::sync::Mutex::new(Some(shutdown_tx));

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    if let Ok(mut guard) = shutdown_tx.lock()
                        && let Some(tx) = guard.take()
                    {
                        let _ = tx.send(());
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

        // Report running
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");

        // Look for config file path from FIPS_CONFIG env var
        let config_path: Option<PathBuf> = std::env::var("FIPS_CONFIG").ok().map(PathBuf::from);

        rt.block_on(super::run_daemon(config_path, async {
            let _ = shutdown_rx.await;
        }));

        // Report stopped
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        Ok(())
    }

    /// Install FIPS as a Windows service (requires Administrator).
    pub fn install_service() -> Result<(), Box<dyn std::error::Error>> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
        )?;

        let exe_path = std::env::current_exe()?;
        let service_info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(SERVICE_DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe_path,
            launch_arguments: vec![OsString::from("--service")],
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };

        let service = match manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG) {
            Ok(s) => s,
            Err(windows_service::Error::Winapi(ref e)) if e.raw_os_error() == Some(0x431) => {
                // ERROR_SERVICE_EXISTS (1073) — open the existing service instead
                println!(
                    "Service '{}' already exists, updating configuration...",
                    SERVICE_NAME
                );
                manager.open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG)?
            }
            Err(e) => return Err(format!("Failed to create service: {}", e).into()),
        };

        // set_description is non-critical — don't fail the install over it
        if let Err(e) = service.set_description(SERVICE_DESCRIPTION) {
            eprintln!("Warning: could not set service description: {}", e);
        }

        println!("Service '{}' installed successfully.", SERVICE_NAME);
        println!("Start it with: sc start {}", SERVICE_NAME);
        println!();
        println!("Configuration: place fips.yaml in one of:");
        println!("  - Current directory");
        println!("  - %APPDATA%\\fips\\fips.yaml");
        println!("  - Set FIPS_CONFIG environment variable");
        Ok(())
    }

    /// Uninstall the FIPS Windows service (requires Administrator).
    pub fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;

        let service = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        )?;

        // Stop the service if running
        if let Ok(status) = service.query_status()
            && status.current_state != ServiceState::Stopped
        {
            println!("Stopping service...");
            let _ = service.stop();
            // Wait briefly for the service to stop
            std::thread::sleep(Duration::from_secs(2));
        }

        service.delete()?;
        println!("Service '{}' uninstalled.", SERVICE_NAME);
        Ok(())
    }
}
