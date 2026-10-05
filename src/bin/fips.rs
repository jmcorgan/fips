//! FIPS daemon binary
//!
//! Loads configuration and creates the top-level node instance.
//! On Windows, can run as a Windows Service when invoked with `--service`.

use clap::Parser;
use fips::config::{IdentitySource, resolve_identity};
use fips::utils::logfile::{ROLL_BYTES, ROLL_KEEP, RollingFile, SharedLog};
use fips::version;
use fips::{Config, Node};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tracing::{debug, error, info, warn};
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

    /// Log to this file, rolled by size, instead of stdout. Overrides
    /// `node.log_file`, and is opened before the configuration loads so that
    /// a configuration error is logged to it too.
    #[arg(long, value_name = "FILE")]
    log_file: Option<PathBuf>,

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

/// The log file the daemon owns, when it owns one: opened from `--log-file`
/// before the configuration loads, from `node.log_file` after it, or by the
/// Windows service. Unset, the log goes to stdout.
///
/// Writes to it are synchronous and unbuffered, so the line logged before a
/// `process::exit` is on disk when the process ends.
static LOG: OnceLock<SharedLog> = OnceLock::new();

/// Open `path` as the daemon's log, with the default limits until the
/// configuration supplies its own, and send panics to it.
fn open_log(path: &Path) -> std::io::Result<()> {
    let log = SharedLog::new(RollingFile::open(path, ROLL_BYTES, ROLL_KEEP)?);
    if LOG.set(log.clone()).is_err() {
        return Ok(());
    }
    // The default hook writes to stderr, which a supervisor that cannot
    // rotate is likely to discard or never look at, and which launchd appends
    // to a file nothing rolls. It still runs where stderr is a terminal.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if echo_to_stderr(true, std::io::stderr().is_terminal()) {
            previous(info);
        }
        log.try_line(&info.to_string());
    }));
    Ok(())
}

/// Whether an error or panic that goes to the log file should also go to
/// stderr: always when no log is open, and otherwise only when stderr is a
/// terminal someone is watching.
///
/// Not under a supervisor: launchd restarts a daemon that exits on a bad
/// config or panics every ten seconds, and the stderr file it appends to is
/// never rolled.
fn echo_to_stderr(log_open: bool, stderr_is_terminal: bool) -> bool {
    !log_open || stderr_is_terminal
}

/// Report an error raised before logging is set up: to the log file when one
/// is open, and to stderr as [`echo_to_stderr`] decides.
fn startup_error(msg: &str) {
    if let Some(log) = LOG.get() {
        log.line(&format!("ERROR {msg}"));
    }
    if echo_to_stderr(LOG.get().is_some(), std::io::stderr().is_terminal()) {
        eprintln!("{msg}");
    }
}

/// What to do with `node.log_file`, given whether `--log-file` or the
/// Windows service already opened a log, which take precedence.
#[derive(Debug, PartialEq)]
enum ConfiguredLog<'a> {
    /// Unset: log to the file already open, or to stdout.
    Unset,
    /// Open it.
    Open(&'a str),
    /// Set, but a log is already open; worth a warning.
    Ignored(&'a str),
}

fn configured_log(configured: Option<&str>, already_open: bool) -> ConfiguredLog<'_> {
    match (configured, already_open) {
        (None, _) => ConfiguredLog::Unset,
        (Some(path), false) => ConfiguredLog::Open(path),
        (Some(path), true) => ConfiguredLog::Ignored(path),
    }
}

/// Run the FIPS daemon (shared between foreground and service modes).
///
/// `config_path` overrides the default config search. `shutdown_signal`
/// is awaited to trigger a graceful stop — in foreground mode this is
/// Ctrl+C / SIGTERM, in service mode it's the service stop event.
async fn run_daemon(
    config_path: Option<PathBuf>,
    log_file: Option<PathBuf>,
    shutdown_signal: impl std::future::Future<Output = ()>,
) {
    // Fatal on failure, as an unusable config is: a daemon that silently ran
    // without the log it was told to keep would present as exactly the
    // missing-logs problem the file exists to solve.
    if let Some(path) = &log_file
        && let Err(e) = open_log(path)
    {
        eprintln!("Cannot open log file {}: {e}", path.display());
        std::process::exit(1);
    }

    // Load configuration before initializing logging so we can use
    // the config's log_level as the tracing filter default.
    let (config, loaded_paths) = if let Some(config_path) = &config_path {
        match Config::load_file(config_path) {
            Ok(config) => (config, vec![config_path.clone()]),
            Err(e) => {
                let msg = format!(
                    "Failed to load configuration from {}: {}",
                    config_path.display(),
                    e
                );
                startup_error(&msg);
                std::process::exit(1);
            }
        }
    } else {
        match Config::load() {
            Ok(result) => result,
            Err(e) => {
                let msg = format!("Failed to load configuration: {}", e);
                startup_error(&msg);
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

    // Where the log goes. With no log file the stream stays on stdout for a
    // supervisor to capture, which is what journald and syslog want and
    // rotate. `node.log_file` is opened here unless `--log-file` or the
    // Windows service already opened one, which take precedence.
    let ignored_log_file =
        match configured_log(config.node.log_file.as_deref(), LOG.get().is_some()) {
            ConfiguredLog::Open(path) => {
                if let Err(e) = open_log(Path::new(path)) {
                    startup_error(&format!("Cannot open log file {path}: {e}"));
                    std::process::exit(1);
                }
                None
            }
            ConfiguredLog::Ignored(path) => Some(path),
            ConfiguredLog::Unset => None,
        };
    let writer = match LOG.get() {
        Some(log) => {
            log.set_limits(config.node.log_max_bytes(), config.node.log_max_files());
            BoxMakeWriter::new(log.clone())
        }
        None => BoxMakeWriter::new(std::io::stdout),
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
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_ansi(LOG.get().is_none() && std::io::stdout().is_terminal())
        .with_writer(writer)
        .log_internal_errors(false)
        .init();

    // Logged first: an operator looking for output that is no longer on
    // stdout needs the path and the limits that govern it.
    if let Some(log) = LOG.get() {
        info!(
            path = %log.path().display(),
            max_bytes = config.node.log_max_bytes(),
            max_files = config.node.log_max_files(),
            "Logging to file"
        );
    }
    if let Some(path) = ignored_log_file {
        warn!(
            configured = path,
            "node.log_file ignored: the log is already open"
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

    // Windows moved its config, key and ACL files from %APPDATA%\fips and
    // /etc/fips to C:\ProgramData\fips; flag a config left behind. The peer
    // ACL reloader reports ACL files left at the old location.
    #[cfg(windows)]
    fips::config::warn_legacy(&loaded_paths);

    // Earlier releases could run a Windows node from \etc\fips, where any
    // local user can create files; flag a config the search loaded there.
    #[cfg(windows)]
    fips::config::warn_legacy_etc_config(&loaded_paths);

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

    // Flag a config or key left in \etc\fips that this run did not use. After
    // identity resolution, which decides whether that key was used.
    #[cfg(windows)]
    fips::config::warn_legacy_etc_unused(&loaded_paths, &resolved.source);

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
    run_daemon(args.config, args.log_file, foreground_shutdown_signal()).await;
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

    rt.block_on(run_daemon(
        args.config,
        args.log_file,
        foreground_shutdown_signal(),
    ));
}

#[cfg(windows)]
mod service {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
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

    /// Open the service log in the config directory, before anything can go
    /// wrong: a service has no console, so without it nothing is recorded.
    ///
    /// A failure leaves the log unset and the daemon runs on without one:
    /// with no console and logging not yet up, nothing could report it.
    fn open_log() {
        let path = Path::new(fips::config::SYSTEM_CONFIG_DIR).join("fips.log");
        let _ = super::open_log(&path);
    }

    /// Start the service dispatcher, which blocks until the service stops.
    pub fn run_as_service() -> Result<(), windows_service::Error> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    /// Entry point called by the Windows service control manager.
    fn service_main(arguments: Vec<OsString>) {
        open_log();
        if let Err(e) = run_service(arguments) {
            let msg = format!("Service error: {:?}", e);
            match super::LOG.get() {
                Some(log) => log.line(&msg),
                None => eprintln!("{msg}"),
            }
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

        rt.block_on(super::run_daemon(config_path, None, async {
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
        let dir = std::path::Path::new(fips::config::SYSTEM_CONFIG_DIR);
        println!(
            "Configuration: the service reads {}",
            dir.join("fips.yaml").display()
        );
        println!("  keep hosts, peers.allow and peers.deny beside it, and fips.key");
        println!("  too when node.identity.persistent is true.");
        println!(
            "Logs: the service writes {}",
            dir.join("fips.log").display()
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_file_flag_takes_precedence_over_config() {
        assert_eq!(configured_log(None, false), ConfiguredLog::Unset);
        assert_eq!(configured_log(None, true), ConfiguredLog::Unset);
        assert_eq!(
            configured_log(Some("a.log"), false),
            ConfiguredLog::Open("a.log")
        );
        assert_eq!(
            configured_log(Some("a.log"), true),
            ConfiguredLog::Ignored("a.log")
        );
    }

    #[test]
    fn errors_reach_stderr_only_without_a_log_or_with_a_terminal() {
        assert!(echo_to_stderr(false, false));
        assert!(echo_to_stderr(false, true));
        assert!(echo_to_stderr(true, true));
        // Under launchd: the log has it, and stderr is a file nothing rolls.
        assert!(!echo_to_stderr(true, false));
    }
}
