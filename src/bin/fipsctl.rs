//! fipsctl — FIPS control client
//!
//! Connects to the FIPS daemon's control socket, sends commands, and
//! pretty-prints the JSON response.
//!
//! On Unix, uses a Unix domain socket for local IPC.
//! On Windows, uses a TCP connection to localhost.

use clap::{Parser, Subcommand};
use fips::config::{write_key_file, write_pub_file};
use fips::upper::hosts::HostMap;
use fips::version;
use fips::{Identity, encode_nsec};
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

/// FIPS control client
#[derive(Parser, Debug)]
#[command(
    name = "fipsctl",
    version = version::short_version(),
    long_version = version::long_version(),
    about = "Control a running FIPS daemon"
)]
struct Cli {
    /// Control socket path override
    #[arg(short = 's', long)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show node information
    Show {
        #[command(subcommand)]
        what: ShowCommands,
    },
    /// Show peer ACL information
    Acl {
        #[command(subcommand)]
        what: AclCommands,
    },
    /// Generate a new FIPS identity keypair
    Keygen {
        /// Output directory for fips.key and fips.pub
        #[arg(short = 'd', long = "dir", default_value_os_t = default_key_dir())]
        dir: PathBuf,
        /// Overwrite existing key files
        #[arg(short = 'f', long = "force")]
        force: bool,
        /// Print nsec and npub to stdout instead of writing files
        #[arg(short = 's', long = "stdout")]
        stdout: bool,
    },
    /// Connect to a peer
    Connect {
        /// Peer identifier: npub (bech32) or hostname from /etc/fips/hosts
        peer: String,
        /// Transport address (e.g., "192.168.1.1:2121")
        address: String,
        /// Transport type: udp, tcp, tor, ethernet
        transport: String,
    },
    /// Disconnect a peer
    Disconnect {
        /// Peer identifier: npub (bech32) or hostname from /etc/fips/hosts
        peer: String,
    },
    /// Diagnose reachability of a mesh endpoint
    Probe {
        /// Target identifier: npub (bech32) or hostname from /etc/fips/hosts
        target: String,
        /// Emit the report as JSON instead of human-readable text
        #[arg(long)]
        json: bool,
        /// Client-side ceiling in seconds. Defaults to the daemon's own
        /// computed budget, which scales with its tick interval.
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// Query historical node statistics
    Stats {
        #[command(subcommand)]
        what: StatsCommands,
    },
    /// Control the built-in profiler (requires a `--features profiling` build)
    #[cfg(feature = "profiling")]
    Profile {
        #[command(subcommand)]
        what: ProfileCommands,
    },
}

#[cfg(feature = "profiling")]
#[derive(Subcommand, Debug)]
enum ProfileCommands {
    /// Profile the rx-loop tick body
    Tick {
        #[command(subcommand)]
        action: ProfileTickAction,
    },
}

#[cfg(feature = "profiling")]
#[derive(Subcommand, Debug)]
enum ProfileTickAction {
    /// Start a capture
    On {
        /// Directory for the capture file (default /var/log/fips)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Stop the running capture
    Off,
    /// Report capture state
    Status,
}

#[derive(Subcommand, Debug)]
enum StatsCommands {
    /// List available history metrics
    List,
    /// Dump current counter values for every protocol metric family
    Metrics,
    /// List peers tracked in the stats history
    Peers,
    /// Fetch a time-series window for a metric
    History {
        /// Metric name (see `fipsctl stats list`). Node-level metrics
        /// need no `--peer`; per-peer metrics require it.
        metric: String,
        /// Peer npub (bech32) or hostname from /etc/fips/hosts for
        /// per-peer metrics
        #[arg(long)]
        peer: Option<String>,
        /// Window duration — `<N>s`, `<N>m`, `<N>h`
        #[arg(long, default_value = "10m")]
        window: String,
        /// Sample resolution — `1s` (fast ring) or `1m` (slow ring)
        #[arg(long, default_value = "1s")]
        granularity: String,
        /// Render a Unicode block sparkline instead of JSON
        #[arg(long)]
        plot: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ShowCommands {
    /// Node status overview
    Status,
    /// Authenticated peers
    Peers,
    /// Active links
    Links,
    /// Spanning tree state
    Tree,
    /// End-to-end sessions
    Sessions,
    /// Bloom filter state
    Bloom,
    /// MMP metrics summary
    Mmp,
    /// Coordinate cache stats
    Cache,
    /// Pending handshake connections
    Connections,
    /// Transport instances
    Transports,
    /// Routing table summary
    Routing,
    /// Identity cache entries (known node pubkeys)
    IdentityCache,
}

#[derive(Subcommand, Debug)]
enum AclCommands {
    /// Loaded peer ACL state
    Show,
}

impl ShowCommands {
    fn command_name(&self) -> &'static str {
        match self {
            ShowCommands::Status => "show_status",
            ShowCommands::Peers => "show_peers",
            ShowCommands::Links => "show_links",
            ShowCommands::Tree => "show_tree",
            ShowCommands::Sessions => "show_sessions",
            ShowCommands::Bloom => "show_bloom",
            ShowCommands::Mmp => "show_mmp",
            ShowCommands::Cache => "show_cache",
            ShowCommands::Connections => "show_connections",
            ShowCommands::Transports => "show_transports",
            ShowCommands::Routing => "show_routing",
            ShowCommands::IdentityCache => "show_identity_cache",
        }
    }
}

impl AclCommands {
    fn command_name(&self) -> &'static str {
        match self {
            AclCommands::Show => "show_acl",
        }
    }
}

fn default_socket_path() -> PathBuf {
    fips::config::default_control_path()
}

/// Send a JSON request to the control socket and return the response.
///
/// On Unix, connects via Unix domain socket.
/// On Windows, connects via TCP to localhost.
#[cfg(unix)]
fn send_request(socket_path: &Path, request_json: &str) -> Result<serde_json::Value, String> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "cannot connect to {}: {}\n\
                 Hint: add your user to the 'fips' group: sudo usermod -aG fips $USER\n\
                 Then log out and back in for the change to take effect.",
                socket_path.display(),
                e
            )
        } else {
            format!(
                "cannot connect to {}: {}\nIs the FIPS daemon running?",
                socket_path.display(),
                e
            )
        }
    })?;

    let timeout = Duration::from_secs(5);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    stream
        .write_all(request_json.as_bytes())
        .map_err(|e| format!("failed to send request: {e}"))?;
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let reader = BufReader::new(&stream);
    let line = reader
        .lines()
        .next()
        .ok_or("no response from daemon")?
        .map_err(|e| format!("failed to read response: {e}"))?;

    serde_json::from_str(&line).map_err(|e| format!("invalid response JSON: {e}"))
}

#[cfg(windows)]
fn send_request(socket_path: &Path, request_json: &str) -> Result<serde_json::Value, String> {
    use std::net::TcpStream;

    let port_str = socket_path.to_string_lossy();
    let port: u16 = match port_str.parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("warning: invalid port '{}', using default 21210", port_str);
            21210
        }
    };
    let addr = format!("127.0.0.1:{port}");

    let mut stream = TcpStream::connect(&addr).map_err(|e| {
        format!(
            "cannot connect to {}: {}\nIs the FIPS daemon running?",
            addr, e
        )
    })?;

    let timeout = Duration::from_secs(5);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    stream
        .write_all(request_json.as_bytes())
        .map_err(|e| format!("failed to send request: {e}"))?;
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let reader = BufReader::new(&stream);
    let line = reader
        .lines()
        .next()
        .ok_or("no response from daemon")?
        .map_err(|e| format!("failed to read response: {e}"))?;

    serde_json::from_str(&line).map_err(|e| format!("invalid response JSON: {e}"))
}

/// Build a request JSON string for a simple command (no params).
fn build_query(command: &str) -> String {
    format!("{{\"command\":\"{command}\"}}\n")
}

/// Build a request JSON string for a command with params.
fn build_command(command: &str, params: serde_json::Value) -> String {
    let req = serde_json::json!({"command": command, "params": params});
    format!("{}\n", serde_json::to_string(&req).unwrap())
}

/// Print a control socket response, handling error status.
fn print_response(value: &serde_json::Value) {
    let status = value
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    if status == "error" {
        let msg = value
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        eprintln!("error: {msg}");
        std::process::exit(1);
    }

    let output = if let Some(data) = value.get("data") {
        serde_json::to_string_pretty(data)
    } else {
        serde_json::to_string_pretty(value)
    };
    println!("{}", output.unwrap_or_else(|_| format!("{value}")));
}

/// Default directory for keygen output.
///
/// Must match the platform's config dir, since the daemon derives key
/// paths from the config file's location.
fn default_key_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(fips::config::SYSTEM_CONFIG_DIR)
    }
    #[cfg(windows)]
    {
        dirs::config_dir()
            .map(|d| d.join("fips"))
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData\\fips"))
    }
}

/// Check if `address` is an IPv6 literal in `fd00::/8` (FIPS mesh ULA range).
///
/// Handles three common syntaxes:
///   - bare IPv6:          `fd9d:...`
///   - bracketed + port:   `[fd9d:...]:2121`
///   - bare IPv6 + port:   `fd9d:...:2121` (ambiguous; accepted if tail is numeric)
fn is_fips_mesh_address(address: &str) -> bool {
    let is_ula = |a: &Ipv6Addr| a.octets()[0] == 0xfd;

    if let Ok(a) = address.parse::<Ipv6Addr>() {
        return is_ula(&a);
    }
    if let Ok(sa) = address.parse::<SocketAddrV6>() {
        return is_ula(sa.ip());
    }
    if let Some((host, port)) = address.rsplit_once(':')
        && port.chars().all(|c| c.is_ascii_digit())
        && !port.is_empty()
    {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(a) = host.parse::<Ipv6Addr>() {
            return is_ula(&a);
        }
    }
    false
}

/// Reject `fd00::/8` addresses for transports that expect a reachable network endpoint.
///
/// FIPS mesh ULAs are derived from npubs and only make sense as destinations
/// inside an already-established mesh — they are not valid udp/tcp/ethernet
/// transport endpoints. Without this check the CLI echoes success while the
/// daemon rejects the bind with EAFNOSUPPORT (issue #61).
fn validate_connect_address(address: &str, transport: &str) -> Result<(), String> {
    let checked = matches!(transport, "udp" | "tcp" | "ethernet");
    if checked && is_fips_mesh_address(address) {
        return Err(format!(
            "'{address}' is a FIPS mesh address (fd00::/8), not a reachable {transport} endpoint.\n\
             Provide the peer's routable IP/hostname and port (e.g., '192.0.2.1:2121' or 'peer.example.com:2121')."
        ));
    }
    Ok(())
}

/// Resolve a peer identifier to an npub.
///
/// If the identifier starts with "npub1", it's returned as-is.
/// Otherwise, it's looked up as a hostname in the hosts file.
fn resolve_peer(peer: &str) -> String {
    if peer.starts_with("npub1") {
        return peer.to_string();
    }

    let hosts = HostMap::load_hosts_file(Path::new(fips::upper::hosts::DEFAULT_HOSTS_PATH));
    match hosts.lookup_npub(peer) {
        Some(npub) => npub.to_string(),
        None => {
            eprintln!("error: unknown host '{peer}'");
            eprintln!(
                "Not found in {} and not an npub.",
                fips::upper::hosts::DEFAULT_HOSTS_PATH
            );
            std::process::exit(1);
        }
    }
}

fn main() {
    let cli = Cli::parse();

    // Commands that don't require a running daemon
    if let Commands::Keygen { dir, force, stdout } = &cli.command {
        let identity = Identity::generate();
        // `keypair()` and `secret_key()` each hand back a whole private key
        // rather than a handle, so both temporaries are bound and erased. The
        // nsec is that same key in another encoding, so it is guarded too.
        let mut our_keypair = identity.keypair();
        let mut secret_key = our_keypair.secret_key();
        let nsec = Zeroizing::new(encode_nsec(&secret_key));
        secret_key.non_secure_erase();
        our_keypair.non_secure_erase();
        let npub = identity.npub();

        if *stdout {
            println!("{}", nsec.as_str());
            println!("{npub}");
            return;
        }

        let key_path = dir.join("fips.key");
        let pub_path = dir.join("fips.pub");

        // The default key directory on macOS/FreeBSD moved from /etc/fips
        // to /usr/local/etc/fips; point at keys stranded at the old path.
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        if std::path::Path::new("/etc/fips/fips.key").exists() && !key_path.exists() {
            eprintln!("note: /etc/fips/fips.key exists but the default key directory");
            eprintln!(
                "      is now {}; that key is no longer used by default.",
                dir.display()
            );
        }

        // symlink_metadata rather than exists: a dangling symlink at the key
        // path reports exists() == false and would slip past the guard.
        if key_path.symlink_metadata().is_ok() && !force {
            eprintln!("error: key file already exists: {}", key_path.display());
            eprintln!("Use --force to overwrite.");
            std::process::exit(1);
        }

        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("error: cannot create directory {}: {e}", dir.display());
            std::process::exit(1);
        }

        if let Err(e) = write_key_file(&key_path, &nsec) {
            eprintln!("error: failed to write key file: {e}");
            std::process::exit(1);
        }

        // Non-fatal: the private key is already on disk by this point, so
        // failing the whole run here would report failure for a keygen that
        // did in fact produce the identity.
        if let Err(e) = write_pub_file(&pub_path, &npub) {
            eprintln!("warning: failed to write pub file: {e}");
        }

        eprintln!("{npub}");
        eprintln!("Key files written to: {}/", dir.display());
        eprintln!();
        eprintln!("NOTE: Set 'node.identity.persistent: true' in fips.yaml");
        eprintln!("      or these keys will be overwritten on next daemon start.");
        return;
    }

    let socket_path = cli.socket.unwrap_or_else(default_socket_path);

    let request = match &cli.command {
        Commands::Show { what } => build_query(what.command_name()),
        Commands::Acl { what } => build_query(what.command_name()),
        Commands::Connect {
            peer,
            address,
            transport,
        } => {
            if let Err(e) = validate_connect_address(address, transport) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
            let npub = resolve_peer(peer);
            build_command(
                "connect",
                serde_json::json!({
                    "npub": npub,
                    "address": address,
                    "transport": transport,
                }),
            )
        }
        Commands::Disconnect { peer } => {
            let npub = resolve_peer(peer);
            build_command("disconnect", serde_json::json!({"npub": npub}))
        }
        Commands::Probe {
            target,
            json,
            timeout,
        } => {
            let npub = resolve_peer(target);
            run_probe(&socket_path, &npub, *json, *timeout);
            return;
        }
        Commands::Stats { what } => match what {
            StatsCommands::List => build_query("show_stats_list"),
            StatsCommands::Metrics => build_query("show_metrics"),
            StatsCommands::Peers => build_query("show_stats_peers"),
            StatsCommands::History {
                metric,
                peer,
                window,
                granularity,
                ..
            } => {
                let mut params = serde_json::json!({
                    "metric": metric,
                    "window": window,
                    "granularity": granularity,
                });
                if let Some(p) = peer {
                    let resolved = resolve_peer(p);
                    params["peer"] = serde_json::json!(resolved);
                }
                build_command("show_stats_history", params)
            }
        },
        #[cfg(feature = "profiling")]
        Commands::Profile { what } => match what {
            ProfileCommands::Tick { action } => match action {
                ProfileTickAction::On { dir } => match dir {
                    Some(dir) => build_command(
                        "profile_tick_on",
                        serde_json::json!({"dir": dir.display().to_string()}),
                    ),
                    None => build_query("profile_tick_on"),
                },
                ProfileTickAction::Off => build_query("profile_tick_off"),
                ProfileTickAction::Status => build_query("profile_tick_status"),
            },
        },
        Commands::Keygen { .. } => unreachable!(),
    };

    // For plot output we need to post-process the JSON response rather
    // than pretty-print it.
    if let Commands::Stats {
        what: StatsCommands::History {
            plot: true, metric, ..
        },
    } = &cli.command
    {
        match send_request(&socket_path, &request) {
            Ok(value) => print_plot(&value, metric),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    match send_request(&socket_path, &request) {
        Ok(value) => print_response(&value),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

/// Render the response as a Unicode block sparkline plot.
fn print_plot(value: &serde_json::Value, metric: &str) {
    let status = value
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    if status == "error" {
        let msg = value
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        eprintln!("error: {msg}");
        std::process::exit(1);
    }

    let data = match value.get("data") {
        Some(d) => d,
        None => {
            eprintln!("error: no data in response");
            std::process::exit(1);
        }
    };

    let values: Vec<f64> = data
        .get("values")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(|v| v.as_f64().unwrap_or(f64::NAN)).collect())
        .unwrap_or_default();
    let unit = data.get("unit").and_then(|v| v.as_str()).unwrap_or("");
    let granularity_seconds = data
        .get("granularity_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    if values.is_empty() {
        println!("{metric}: no data yet");
        return;
    }

    let (min, max) = values
        .iter()
        .filter(|v| !v.is_nan())
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &v| {
            (lo.min(v), hi.max(v))
        });
    let (min, max) = if min.is_finite() {
        (min, max)
    } else {
        (0.0, 0.0)
    };
    let last = values
        .iter()
        .rev()
        .find(|v| !v.is_nan())
        .copied()
        .unwrap_or(f64::NAN);
    let width_secs = (values.len() as u64) * granularity_seconds;
    let gap_count = values.iter().filter(|v| v.is_nan()).count();

    println!(
        "{metric} ({unit}) — {n} samples @ {g}s = {w}s window{gap}",
        n = values.len(),
        g = granularity_seconds,
        w = width_secs,
        gap = if gap_count > 0 {
            format!(" ({gap_count} gaps)")
        } else {
            String::new()
        },
    );
    let last_str = if last.is_nan() {
        "-".to_string()
    } else {
        format!("{last:.3}")
    };
    println!("  min={min:.3} max={max:.3} last={last_str}");
    println!("  {}", sparkline(&values, min, max));
}

/// Render a slice of values as Unicode block characters.
///
/// Uses eight discrete levels: `▁▂▃▄▅▆▇█`. Constant series and empty
/// inputs render as a single-level line (`▄`).
fn sparkline(values: &[f64], min: f64, max: f64) -> String {
    const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let range = max - min;
    values
        .iter()
        .map(|&v| {
            if v.is_nan() {
                ' '
            } else if !range.is_finite() || range <= 0.0 {
                BLOCKS[3]
            } else {
                let norm = ((v - min) / range).clamp(0.0, 1.0);
                let idx = (norm * (BLOCKS.len() as f64 - 1.0)).round() as usize;
                BLOCKS[idx.min(BLOCKS.len() - 1)]
            }
        })
        .collect()
}

/// Run a probe: start it, poll while the daemon works, render as it goes.
///
/// Every control round-trip returns immediately; the stages run daemon-side on
/// its tick. The client ceiling is sized from the budget the daemon computed,
/// rather than hard-coded, so a node with a long tick still works.
///
/// Each poll carries the whole report as it stands, stages included, so the
/// stage block is drawn from the first response rather than withheld until the
/// probe finishes. `--json` still emits one document at the end: a script
/// parsing the report should not have to skip past progress output.
fn run_probe(socket_path: &Path, npub: &str, json: bool, timeout_secs: Option<u64>) {
    let start = build_command("probe_start", serde_json::json!({"npub": npub}));
    let value = match send_request(socket_path, &start) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    let data = probe_data_or_exit(&value);
    let probe_id = data.get("probe_id").and_then(|v| v.as_u64()).unwrap_or(0);
    let budget_ms = data
        .get("budget_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(30_000);
    let ceiling_ms = timeout_secs.map_or(budget_ms + 5_000, |s| s * 1000);

    let poll = build_command("probe_poll", serde_json::json!({"probe_id": probe_id}));
    let mut progress = (!json).then(ProbeProgress::new);
    let mut waited_ms = 0u64;
    loop {
        std::thread::sleep(POLL_INTERVAL);
        waited_ms += POLL_INTERVAL.as_millis() as u64;

        let value = match send_request(socket_path, &poll) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        };
        let data = probe_data_or_exit(&value);
        let report = data
            .get("report")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let done = data.get("state").and_then(|v| v.as_str()) == Some("done");
        if done {
            match progress.as_mut() {
                Some(progress) => progress.finish(&report),
                None => print_json(&report),
            }
            let overall = report
                .get("overall")
                .and_then(|v| v.as_str())
                .unwrap_or("failed");
            std::process::exit(if overall == "ok" { 0 } else { 1 });
        }
        if let Some(progress) = progress.as_mut() {
            progress.update(&report);
        }

        if waited_ms >= ceiling_ms {
            // Best effort: the daemon-side deadline cleans up regardless.
            let cancel = build_command("probe_cancel", serde_json::json!({"probe_id": probe_id}));
            let _ = send_request(socket_path, &cancel);
            eprintln!("error: probe did not complete within {ceiling_ms} ms");
            std::process::exit(1);
        }
    }
}

/// Unwrap a control response's `data`, exiting on an error status.
fn probe_data_or_exit(value: &serde_json::Value) -> serde_json::Value {
    if value.get("status").and_then(|v| v.as_str()) == Some("error") {
        let msg = value
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        eprintln!("error: {msg}");
        std::process::exit(1);
    }
    value
        .get("data")
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

/// First 8 hex characters of an address, the `fipstop` convention.
fn short_addr(addr: &str) -> String {
    addr.chars().take(8).collect()
}

fn field<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v.get(key).and_then(|f| f.as_str()).unwrap_or("")
}

/// Render a coordinate path root-first, terminating in the given marker.
fn render_coords(coords: &serde_json::Value, marker: &str) -> String {
    let entries: Vec<String> = coords
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(short_addr)
                .collect()
        })
        .unwrap_or_default();
    if entries.is_empty() {
        return "-".to_string();
    }
    if entries.len() == 1 {
        return format!("{} [root]", entries[0]);
    }
    let mut rev: Vec<String> = entries.into_iter().rev().collect();
    let last = rev.len() - 1;
    rev[last] = format!("{} [{marker}]", rev[last]);
    rev.join(" > ")
}

/// How often the client asks the daemon for the report as it stands.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Width the live block is clipped to. A row that wraps would occupy two
/// screen lines, and the redraw moves the cursor up by row count, so a wrap
/// would leave the previous frame's tail on screen. Settled rows print in full
/// once the block is done.
const LIVE_WIDTH: usize = 78;

/// Spinner frames for the stage currently running.
const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// The four stages, in the order the probe runs them.
const STAGES: [&str; 5] = ["bloom", "discovery", "path", "session", "rtt"];

/// The whole up-then-down tree walk on one line, this node to the target,
/// with the least common ancestor emphasised.
///
/// Both coordinate lists are stored leaf-first, so ours is walked as it
/// stands, from self up to the ancestor, and theirs supplies the descent:
/// everything below the ancestor, reversed, ending at the target. When the
/// target is itself the ancestor there is no descent and the line ends on the
/// emphasised address, which is correct rather than a special case.
fn walk_line(path: &serde_json::Value, lca: &str, tty: bool) -> String {
    let coords = |key: &str| -> Vec<String> {
        path.get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(short_addr)
                    .collect()
            })
            .unwrap_or_default()
    };
    let lca = short_addr(lca);
    let ours = coords("our_coords");
    let theirs = coords("their_coords");
    if ours.is_empty() {
        return "-".to_string();
    }

    let climb = ours
        .iter()
        .position(|a| *a == lca)
        .map_or(ours.len(), |i| i + 1);
    let mut chain: Vec<String> = ours[..climb].to_vec();
    let lca_at = chain.len() - 1;
    let descend = theirs.iter().position(|a| *a == lca).unwrap_or(0);
    chain.extend(theirs[..descend].iter().rev().cloned());

    let last = chain.len() - 1;
    chain
        .iter()
        .enumerate()
        .map(|(i, addr)| {
            let addr = if i == lca_at {
                bold(addr, tty)
            } else {
                addr.clone()
            };
            match i {
                0 => format!("{addr} [self]"),
                i if i == last => format!("{addr} [target]"),
                _ => addr,
            }
        })
        .collect::<Vec<_>>()
        .join(" > ")
}

/// Emphasise, on a terminal only. Escape sequences in a redirected file or a
/// pipe would be noise in exactly the place a report gets pasted from.
fn bold(text: &str, tty: bool) -> String {
    if tty {
        format!("\x1b[1m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// One stage's row, in whatever state that stage is in.
struct StageRow {
    name: &'static str,
    verdict: String,
    /// The machine-stable discriminator, kept as its own field because the
    /// block's tail rule keys on it rather than on the rendered text.
    reason: String,
    text: String,
    elapsed_ms: Option<u64>,
    /// The stage has reached a verdict it will not leave.
    settled: bool,
    /// Detail lines rendered under the row. Only discovery has any: one per
    /// request it sent.
    subs: Vec<String>,
}

impl StageRow {
    /// `name [spinner] verdict elapsed text`, in fixed columns so the live
    /// block and the settled block align with each other.
    fn line(&self, spin: Option<char>) -> String {
        let mark = match spin {
            Some(c) if self.verdict == "running" => c,
            _ => ' ',
        };
        let elapsed = match self.elapsed_ms {
            Some(ms) => format!("{:.1}s", ms as f64 / 1000.0),
            None => String::new(),
        };
        let line = format!(
            "{:<9} {mark} {:<8} {:>6}  {}",
            self.name, self.verdict, elapsed, self.text
        );
        line.trim_end().to_string()
    }
}

/// Build every stage's row from a report, running or finished.
///
/// The elapsed column comes from one clock throughout: a settled stage carries
/// its own tick-quantized figure, and the running stage gets the report's
/// elapsed less the stages already accounted for. Nothing here is measured
/// client-side, so the numbers a viewer watches are the ones the final report
/// prints.
fn stage_rows(report: &serde_json::Value) -> Vec<StageRow> {
    let total_ms = report
        .get("elapsed_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let mut accounted = 0u64;
    let empty = serde_json::Value::Null;
    let mut rows = Vec::with_capacity(STAGES.len());
    for name in STAGES {
        let stage = report.get(name).unwrap_or(&empty);
        let verdict = field(stage, "verdict");
        let settled = matches!(verdict, "ok" | "failed" | "skipped");
        let text = if settled {
            settled_text(name, stage)
        } else if verdict == "running" {
            running_text(name, stage)
        } else {
            String::new()
        };
        let stage_ms = stage.get("elapsed_ms").and_then(|v| v.as_u64());
        let elapsed_ms = match (stage_ms, verdict) {
            (Some(ms), _) => {
                accounted = accounted.saturating_add(ms);
                Some(ms)
            }
            (None, "running") => Some(total_ms.saturating_sub(accounted)),
            (None, _) => None,
        };
        let subs = if name == "discovery" {
            attempt_lines(stage, verdict)
        } else {
            Vec::new()
        };
        rows.push(StageRow {
            name,
            verdict: verdict.to_string(),
            reason: field(stage, "reason").to_string(),
            text,
            elapsed_ms,
            settled,
            subs,
        });
    }

    // Drop the tail of stages that were never attempted. A failure marks
    // everything behind it `not_reached`, and printing that three times says
    // nothing the failed row has not already said.
    //
    // Keyed on `not_reached` rather than on the position of the failure,
    // because the two are not the same thing: a failed path stage does not
    // stop the probe -- the preview touches nothing and the session can still
    // succeed where it named no hop -- so the rows behind that one describe
    // work that really happened and must survive. A skip is kept for the same
    // reason: it is a result, naming why a stage was unnecessary.
    while rows.len() > 1 && rows.last().is_some_and(|r| r.reason == "not_reached") {
        rows.pop();
    }
    rows
}

/// One line per LookupRequest the discovery stage has sent, in order.
///
/// The daemon publishes the attempt in flight and its own ladder, so each
/// line can say how long that attempt was given. The parenthesised figure is
/// that configured timeout, not a measurement: every attempt before the last
/// is known to have run out, and only the last one's fate is open.
///
/// `SPIN_HERE` marks the attempt still in flight; the renderer substitutes
/// the current frame, or a space when it is not animating.
fn attempt_lines(stage: &serde_json::Value, verdict: &str) -> Vec<String> {
    let Some(attempts) = stage.get("attempts").and_then(|v| v.as_u64()) else {
        return Vec::new();
    };
    let ladder: Vec<u64> = stage
        .get("attempt_timeouts_secs")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_u64()).collect())
        .unwrap_or_default();
    (1..=attempts)
        .map(|n| {
            let last = n == attempts;
            let status = match (last, verdict) {
                (true, "ok") => "replied",
                (true, "running") => "waiting",
                _ => "no reply",
            };
            let timeout = ladder
                .get((n - 1) as usize)
                .map_or_else(String::new, |secs| format!("({secs}s)"));
            let mark = if last && verdict == "running" {
                SPIN_HERE
            } else {
                " "
            };
            format!("  attempt {n:<3}{mark} {status:<9} {timeout}")
                .trim_end()
                .to_string()
        })
        .collect()
}

/// Placeholder the renderer swaps for the spinner frame, so building a line
/// stays a pure function of the report.
const SPIN_HERE: &str = "\u{1}";

/// Every line of the stage block, rows and their detail lines together, with
/// `spin` supplying the animation frame or `None` for a settled render.
///
/// One builder serves both the live block and the final one, because on a
/// terminal the first is erased and replaced by the second and they have to
/// agree line for line.
fn block_lines(rows: &[StageRow], spin: Option<char>) -> Vec<String> {
    let mark = spin.unwrap_or(' ').to_string();
    let mut lines = Vec::new();
    for row in rows {
        lines.push(row.line(spin));
        lines.extend(row.subs.iter().map(|sub| sub.replace(SPIN_HERE, &mark)));
    }
    lines
}

/// What a stage says once it has a verdict. This is the text the report has
/// always printed, and it keys on `reason` rather than on the verdict.
fn settled_text(name: &str, stage: &serde_json::Value) -> String {
    match name {
        "bloom" => match field(stage, "reason") {
            "" => match stage.get("fanout").and_then(|v| v.as_u64()) {
                Some(1) => "claimed by a peer filter, request sent".to_string(),
                Some(n) => format!("claimed by a peer filter, request sent to {n} peers"),
                None => "claimed by a peer filter".to_string(),
            },
            "cached" => "coordinates already cached".to_string(),
            "direct_peer" => "target is a directly connected peer".to_string(),
            "bloom_miss" => "no peer filter holds this address".to_string(),
            "backoff_suppressed" => "held down by lookup backoff".to_string(),
            "no_tree_peers" => "claimed, but no tree peer to ask".to_string(),
            other => other.replace('_', " "),
        },
        "discovery" => match field(stage, "reason") {
            "" => "coordinates from mesh lookup".to_string(),
            "cached" | "direct_peer" => "no lookup needed".to_string(),
            "no_response" => match stage.get("attempts").and_then(|v| v.as_u64()) {
                Some(1) => "no reply to 1 request".to_string(),
                Some(n) => format!("no reply to {n} requests"),
                None => "no reply".to_string(),
            },
            "already_pending" => "joined a lookup already in flight, which failed".to_string(),
            other => other.replace('_', " "),
        },
        "path" => "computed locally from coordinates, not an observed path".to_string(),
        "session" => match field(stage, "reason") {
            "" => "FSP session established (XK handshake)".to_string(),
            "preexisting" => "a session to this endpoint already existed".to_string(),
            "send_error" => format!("could not send: {}", field(stage, "detail")),
            "handshake_timeout" => "gave up waiting for the handshake to complete".to_string(),
            other => other.replace('_', " "),
        },
        _ => rtt_text(stage),
    }
}

/// What a stage says while it is still working. Deliberately narrower than the
/// settled text: it may only report what the daemon has actually observed, so
/// a running row never previews an outcome.
fn running_text(name: &str, stage: &serde_json::Value) -> String {
    let count = |key: &str| stage.get(key).and_then(|v| v.as_u64());
    match name {
        "bloom" => "asking the peer filters".to_string(),
        "discovery" => match count("attempts") {
            Some(_) => "waiting for a reply".to_string(),
            None => "sending the first request".to_string(),
        },
        "path" => "computing from coordinates".to_string(),
        "session" => "XK handshake in flight".to_string(),
        _ => match count("reports_seen").unwrap_or(0) {
            0 => "waiting for a receiver report".to_string(),
            1 => "waiting for a usable timestamp echo (1 report so far)".to_string(),
            n => format!("waiting for a usable timestamp echo ({n} reports so far)"),
        },
    }
}

/// Clip to a character count, never a byte index: a display name and a session
/// error both reach here from the far side of the mesh and may be non-ascii.
fn clip(line: &str, width: usize) -> String {
    if line.chars().count() <= width {
        return line.to_string();
    }
    let mut out: String = line.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Draws the stage block while the probe runs.
///
/// On a terminal the block is redrawn in place each poll, so what the viewer
/// watches settles into the final stage block. Off a terminal there is no
/// cursor to move, so each row is printed once, at the moment it settles, and
/// the transcript ends up the same block a terminal leaves behind.
struct ProbeProgress {
    tty: bool,
    /// Rows the last frame left on screen, and so the distance to move up.
    drawn: usize,
    /// Rows already printed, off a terminal.
    emitted: usize,
    frame: usize,
    header: bool,
}

impl ProbeProgress {
    fn new() -> Self {
        Self {
            tty: std::io::stdout().is_terminal(),
            drawn: 0,
            emitted: 0,
            frame: 0,
            header: false,
        }
    }

    /// Render one poll's report.
    fn update(&mut self, report: &serde_json::Value) {
        self.header(report);
        let rows = stage_rows(report);
        if self.tty {
            self.redraw(&rows);
        } else {
            self.emit(&rows);
        }
    }

    /// The probe is over: settle the block, then print the rest of the report.
    fn finish(&mut self, report: &serde_json::Value) {
        self.header(report);
        if self.tty {
            self.erase();
            probe_stages(report);
        } else {
            self.emit(&stage_rows(report));
        }
        probe_detail(report, self.tty);
    }

    /// The target block, printed once, above the stage block.
    fn header(&mut self, report: &serde_json::Value) {
        if !self.header {
            probe_header(report);
            self.header = true;
        }
    }

    fn redraw(&mut self, rows: &[StageRow]) {
        let spin = SPINNER[self.frame % SPINNER.len()];
        let lines = block_lines(rows, Some(spin));
        let mut out = String::new();
        if self.drawn > 0 {
            out.push_str(&format!("\x1b[{}A", self.drawn));
        }
        for line in &lines {
            out.push_str("\x1b[2K");
            out.push_str(&clip(line, LIVE_WIDTH));
            out.push('\n');
        }
        // A failure shortens the block, so the rows the previous frame drew
        // below the new last one have to be blanked and the cursor walked
        // back up over them. Without this the old "session pending" line
        // stays on screen under a report that has stopped mentioning it.
        let stale = self.drawn.saturating_sub(lines.len());
        for _ in 0..stale {
            out.push_str("\x1b[2K\n");
        }
        if stale > 0 {
            out.push_str(&format!("\x1b[{stale}A"));
        }
        print!("{out}");
        let _ = std::io::stdout().flush();
        self.drawn = lines.len();
        self.frame += 1;
    }

    /// Print rows that have settled since the last call, in stage order.
    fn emit(&mut self, rows: &[StageRow]) {
        for line in self.settled_since(rows) {
            println!("{line}");
        }
    }

    /// Lines for the rows that have settled since the last call. Stages settle
    /// in order, so this stops at the first one that has not, and a row is
    /// never returned twice.
    fn settled_since(&mut self, rows: &[StageRow]) -> Vec<String> {
        let mut lines = Vec::new();
        while let Some(row) = rows.get(self.emitted).filter(|r| r.settled) {
            lines.extend(block_lines(std::slice::from_ref(row), None));
            self.emitted += 1;
        }
        lines
    }

    /// Take the live block back off the screen. Its rows are clipped to fit one
    /// screen line and the settled text can be longer, so the block is erased
    /// and reprinted rather than overwritten in place.
    fn erase(&mut self) {
        if self.drawn == 0 {
            return;
        }
        print!("\x1b[{}A", self.drawn);
        for _ in 0..self.drawn {
            println!("\x1b[2K");
        }
        print!("\x1b[{}A", self.drawn);
        let _ = std::io::stdout().flush();
        self.drawn = 0;
    }
}

/// Human-readable text for the rtt stage.
fn rtt_text(rtt: &serde_json::Value) -> String {
    let reports = rtt
        .get("reports_seen")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    match field(rtt, "reason") {
        "" => match rtt.get("rtt_ms").and_then(|v| v.as_u64()) {
            Some(ms) => format!("{ms} ms round trip ({reports} report exchange)"),
            None => "measured".to_string(),
        },
        "no_report" => "no receiver report of any kind within the budget".to_string(),
        "no_echo" => "reports arrived but none carried a usable timestamp echo".to_string(),
        "sub_millisecond" => format!(
            "reports arrived but every sample measured under 1 ms ({reports} reports) \
             -- expected on loopback and same-host meshes"
        ),
        "bad_timestamp_echo" => format!(
            "receiver reports carried timestamp echoes that failed arithmetic \
             validation ({reports} reports). The echo was stale, bogus, or the \
             session clock wrapped. Worth investigating."
        ),
        "not_reached" => "not reached".to_string(),
        other => other.to_string(),
    }
}

/// The closing paragraph, which must not claim reachability it did not observe.
fn overall_note(report: &serde_json::Value) -> Option<&'static str> {
    if field(report, "overall") != "partial" {
        return None;
    }
    match field(report.get("rtt")?, "reason") {
        "no_report" => Some(
            "          The handshake completed, so our packets reached them. Nothing has\n\
             \x20         come back since, so the reverse path may be broken and this\n\
             \x20         endpoint may be reachable in one direction only.",
        ),
        "no_echo" | "sub_millisecond" | "bad_timestamp_echo" => Some(
            "          The endpoint IS reachable: the session handshake completed end to\n\
             \x20         end and receiver reports came back. Only the round-trip\n\
             \x20         measurement did not land inside the budget.",
        ),
        _ => None,
    }
}

/// Emit the report as JSON. `--json` does this once, when the probe ends.
fn print_json(report: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(report).unwrap_or_else(|_| format!("{report}"))
    );
}

/// The target block, which names what is being probed.
fn probe_header(report: &serde_json::Value) {
    let target = report
        .get("target")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    println!(
        "probe {} ({})",
        field(&target, "display_name"),
        field(&target, "npub")
    );
    println!("  node_addr  {}", field(&target, "node_addr"));
    println!("  ipv6       {}", field(&target, "ipv6_addr"));
    println!();
}

/// The four stage rows, settled and unclipped.
fn probe_stages(report: &serde_json::Value) {
    for line in block_lines(&stage_rows(report), None) {
        println!("{line}");
    }
}

/// Everything below the stage block: the computed path, what the probe left
/// behind, and the overall verdict.
fn probe_detail(report: &serde_json::Value, tty: bool) {
    let empty = serde_json::Value::Null;
    let path = report.get("path").unwrap_or(&empty);
    let session = report.get("session").unwrap_or(&empty);

    // A probe that failed before the path stage has nothing to say about the
    // route. Printing the section anyway restates the failure as "no coords"
    // and "no next hop", which reads as two further findings.
    if field(path, "reason") == "not_reached" {
        probe_close(report);
        return;
    }

    println!();
    println!("path (locally computed; this is the route this node WOULD select, not a");
    println!("traceroute -- no hop beyond the first was contacted)");
    // Absent coordinates are not a topology finding. A resolve failure and a
    // freshly peered neighbour both leave them absent, and neither says
    // anything about the spanning tree, so the tree lines are omitted rather
    // than printed from defaults.
    if path
        .get("coords_known")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        println!(
            "  ours       {}   depth {}",
            render_coords(path.get("our_coords").unwrap_or(&empty), "self"),
            path.get("our_depth").and_then(|v| v.as_u64()).unwrap_or(0)
        );
        println!(
            "  theirs     {}   depth {}",
            render_coords(path.get("their_coords").unwrap_or(&empty), "target"),
            path.get("their_depth")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        );
        println!();
        match path.get("lca").and_then(|v| v.as_str()) {
            Some(lca) => println!("  path:      {}", walk_line(path, lca, tty)),
            None => println!("  path:      none (different spanning-tree roots)"),
        }
        if let (Some(up), Some(down), Some(dist)) = (
            path.get("tree_hops_up").and_then(|v| v.as_u64()),
            path.get("tree_hops_down").and_then(|v| v.as_u64()),
            path.get("tree_distance").and_then(|v| v.as_u64()),
        ) {
            println!(
                "  tree walk  {up} up, {down} down  (tree distance {dist}; upper bound, \
                 crosslinks may shorten it)"
            );
        }
    } else {
        println!("  coords     none cached for this target, so no tree walk was computed");
    }
    match path.get("next_hop") {
        Some(hop) if !hop.is_null() => {
            println!(
                "  next hop   {} ({})  class {}",
                short_addr(field(hop, "node_addr")),
                field(hop, "display_name"),
                field(hop, "class")
            );
            if hop
                .get("leaves_tree_walk")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                println!("             (leaves the tree walk above; the real path is shorter");
                println!("              than the tree distance)");
            }
        }
        _ => println!("  next hop   none ({})", field(path, "no_hop_reason")),
    }
    if let Some(mtu) = session.get("path_mtu").and_then(|v| v.as_u64()) {
        println!("  path mtu   {mtu} bytes (observed)");
    }

    probe_close(report);
}

/// What the probe left behind, and the verdict. Printed whether or not there
/// was a route to describe.
fn probe_close(report: &serde_json::Value) {
    let empty = serde_json::Value::Null;
    println!();
    let cleanup = report.get("cleanup").unwrap_or(&empty);
    let torn = cleanup
        .get("session_created_and_torn_down")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let cleanup_text = if torn {
        "session was opened by this probe and has been torn down".to_string()
    } else if let Some(reason) = cleanup.get("left_intact_reason").and_then(|v| v.as_str()) {
        format!("session left in place ({reason})")
    } else {
        "nothing to clean up".to_string()
    };
    println!("cleanup   {cleanup_text}");
    let warmups = cleanup
        .get("warmups_sent")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if warmups > 0 && !torn {
        println!(
            "          {warmups} coords-warmup message(s) were sent on a session this \
             probe does not own"
        );
    }
    let tick = report.get("tick_ms").and_then(|v| v.as_u64()).unwrap_or(0);
    println!(
        "overall   {}  ({} ms; stage timings are quantized to the {tick} ms tick)",
        field(report, "overall"),
        report
            .get("elapsed_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    );
    if let Some(note) = overall_note(report) {
        println!("{note}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // macOS and FreeBSD packaging ship config under /usr/local/etc/fips/.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn test_default_key_dir_follows_packaging_layout() {
        assert_eq!(default_key_dir(), PathBuf::from("/usr/local/etc/fips"));
    }

    // Other Unix keeps the historic /etc/fips/ location.
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "freebsd"))))]
    #[test]
    fn test_default_key_dir_keeps_etc_fips_layout() {
        assert_eq!(default_key_dir(), PathBuf::from("/etc/fips"));
    }

    #[test]
    fn test_acl_show_command_name() {
        assert_eq!(AclCommands::Show.command_name(), "show_acl");
    }

    #[test]
    fn test_cli_parses_acl_show() {
        let cli = Cli::try_parse_from(["fipsctl", "acl", "show"]).unwrap();

        assert!(matches!(
            cli.command,
            Commands::Acl {
                what: AclCommands::Show
            }
        ));
    }

    #[test]
    fn test_cli_parses_probe() {
        let cli = Cli::try_parse_from(["fipsctl", "probe", "hydra", "--json"]).unwrap();
        match cli.command {
            Commands::Probe {
                target,
                json,
                timeout,
            } => {
                assert_eq!(target, "hydra");
                assert!(json);
                assert_eq!(timeout, None);
            }
            other => panic!("expected a probe command, got {other:?}"),
        }
    }

    #[test]
    fn renders_coordinates_root_first_and_truncated() {
        let coords = serde_json::json!([
            "4d2201ff00000000000000000000dead",
            "91b40c6e00000000000000000000beef"
        ]);
        // Stored self -> root; rendered root -> self, 8 hex per entry.
        assert_eq!(render_coords(&coords, "self"), "91b40c6e > 4d2201ff [self]");
    }

    /// A report mid-probe: resolve settled, session in flight, rtt untouched.
    fn running_report() -> serde_json::Value {
        serde_json::json!({
            "elapsed_ms": 3400,
            "bloom": {"verdict": "ok", "reason": null, "elapsed_ms": 0, "fanout": 3},
            "discovery": {"verdict": "ok", "reason": null, "elapsed_ms": 2000, "attempts": 2,
                          "attempt_timeouts_secs": [1, 2, 4, 8]},
            "path": {"verdict": "ok", "reason": null, "elapsed_ms": 0},
            "session": {"verdict": "running", "reason": null, "elapsed_ms": null},
            "rtt": {"verdict": "pending", "reason": null, "elapsed_ms": null,
                    "reports_seen": 0},
        })
    }

    /// Index of a stage in the block, by name.
    fn row_at(rows: &[StageRow], name: &str) -> usize {
        rows.iter().position(|r| r.name == name).unwrap_or_else(|| {
            panic!(
                "no {name} row in {:?}",
                rows.iter().map(|r| r.name).collect::<Vec<_>>()
            )
        })
    }

    #[test]
    fn a_running_stage_row_reports_progress_and_never_previews_its_outcome() {
        // The trap: every settled text keys on `reason`, which is null while a
        // stage runs, so the success arm renders for a stage that has not
        // succeeded. A running session row must not claim the handshake.
        let rows = stage_rows(&running_report());
        let session = &rows[row_at(&rows, "session")];
        assert_eq!(session.verdict, "running");
        assert!(!session.settled);
        assert_eq!(session.text, "XK handshake in flight");
        assert!(
            !session.text.contains("established"),
            "running row previewed the outcome: {}",
            session.text
        );
    }

    #[test]
    fn the_block_ends_at_the_first_failure() {
        // A bloom failure marks the four stages behind it "not reached",
        // which is bookkeeping rather than a result worth a row each.
        let report = serde_json::json!({
            "elapsed_ms": 700,
            "bloom": {"verdict": "failed", "reason": "bloom_miss", "elapsed_ms": 700,
                      "fanout": null},
            "discovery": {"verdict": "skipped", "reason": "not_reached"},
            "path": {"verdict": "skipped", "reason": "not_reached"},
            "session": {"verdict": "skipped", "reason": "not_reached"},
            "rtt": {"verdict": "skipped", "reason": "not_reached"},
        });
        let rows = stage_rows(&report);
        assert_eq!(
            rows.len(),
            1,
            "rows: {:?}",
            rows.iter().map(|r| r.name).collect::<Vec<_>>()
        );
        assert_eq!(rows[0].name, "bloom");
        assert_eq!(rows[0].text, "no peer filter holds this address");
    }

    #[test]
    fn a_failed_path_keeps_the_stages_that_ran_after_it() {
        // The path preview names no hop and the session succeeds anyway,
        // which is why the path stage does not stop the probe. Dropping rows
        // at the first failure rather than at the first unattempted stage
        // would hide a successful handshake behind a failed preview.
        let report = serde_json::json!({
            "elapsed_ms": 3000,
            "bloom": {"verdict": "ok", "reason": null, "elapsed_ms": 0, "fanout": 1},
            "discovery": {"verdict": "ok", "reason": null, "elapsed_ms": 1000, "attempts": 1,
                          "attempt_timeouts_secs": [1, 2, 4, 8]},
            "path": {"verdict": "failed", "reason": "no_next_hop", "elapsed_ms": 0},
            "session": {"verdict": "ok", "reason": null, "elapsed_ms": 1000},
            "rtt": {"verdict": "ok", "reason": null, "elapsed_ms": 1000, "rtt_ms": 22,
                    "reports_seen": 1},
        });
        let rows = stage_rows(&report);
        assert_eq!(rows.len(), 5, "a failed preview must not hide what ran");
        assert_eq!(rows[row_at(&rows, "path")].verdict, "failed");
        assert_eq!(rows[row_at(&rows, "session")].verdict, "ok");
    }

    #[test]
    fn a_skip_is_a_result_and_keeps_the_rows_behind_it() {
        // The direct-peer case: the lookup is unnecessary rather than broken,
        // so every later stage still ran and still has something to report.
        let report = serde_json::json!({
            "elapsed_ms": 2000,
            "bloom": {"verdict": "skipped", "reason": "direct_peer", "elapsed_ms": 0},
            "discovery": {"verdict": "skipped", "reason": "direct_peer", "elapsed_ms": 0},
            "path": {"verdict": "ok", "reason": null, "elapsed_ms": 0},
            "session": {"verdict": "ok", "reason": null, "elapsed_ms": 1000},
            "rtt": {"verdict": "ok", "reason": null, "elapsed_ms": 1000, "rtt_ms": 17,
                    "reports_seen": 1},
        });
        assert_eq!(stage_rows(&report).len(), 5);
    }

    #[test]
    fn a_pending_stage_row_says_nothing_at_all() {
        let rows = stage_rows(&running_report());
        let rtt = &rows[row_at(&rows, "rtt")];
        assert_eq!(rtt.verdict, "pending");
        assert_eq!(rtt.text, "");
        assert_eq!(rtt.elapsed_ms, None);
    }

    #[test]
    fn the_running_stage_elapsed_comes_from_the_report_clock_not_a_client_one() {
        // 3400 ms of probe, 2000 of it resolve and 0 path, leaves 1400 in the
        // session stage that has not finished to report its own figure.
        let rows = stage_rows(&running_report());
        assert_eq!(rows[row_at(&rows, "discovery")].elapsed_ms, Some(2000));
        assert_eq!(rows[row_at(&rows, "path")].elapsed_ms, Some(0));
        assert_eq!(rows[row_at(&rows, "session")].elapsed_ms, Some(1400));
    }

    #[test]
    fn every_request_the_discovery_stage_sent_gets_its_own_line() {
        let report = serde_json::json!({
            "elapsed_ms": 7100,
            "bloom": {"verdict": "ok", "reason": null, "elapsed_ms": 0, "fanout": 1},
            "discovery": {"verdict": "running", "reason": null, "elapsed_ms": null,
                          "attempts": 3, "attempt_timeouts_secs": [1, 2, 4, 8]},
            "path": {"verdict": "pending"},
            "session": {"verdict": "pending"},
            "rtt": {"verdict": "pending"},
        });
        let rows = stage_rows(&report);
        let subs = &rows[row_at(&rows, "discovery")].subs;
        assert_eq!(subs.len(), 3, "one line per request sent: {subs:?}");
        assert!(
            subs[0].contains("no reply") && subs[0].contains("(1s)"),
            "{}",
            subs[0]
        );
        assert!(
            subs[1].contains("no reply") && subs[1].contains("(2s)"),
            "{}",
            subs[1]
        );
        // Only the attempt still in flight is undecided, and only it animates.
        assert!(
            subs[2].contains("waiting") && subs[2].contains("(4s)"),
            "{}",
            subs[2]
        );
        assert!(subs[2].contains(SPIN_HERE), "{}", subs[2]);
        assert!(!subs[0].contains(SPIN_HERE), "{}", subs[0]);
    }

    #[test]
    fn the_last_request_is_marked_replied_once_coordinates_arrive() {
        let rows = stage_rows(&running_report());
        let subs = &rows[row_at(&rows, "discovery")].subs;
        assert_eq!(subs.len(), 2);
        assert!(subs[0].contains("no reply"), "{}", subs[0]);
        assert!(subs[1].contains("replied"), "{}", subs[1]);
    }

    #[test]
    fn the_spinner_marks_the_running_row_and_no_other() {
        let rows = stage_rows(&running_report());
        let session = row_at(&rows, "session");
        assert!(!rows[0].line(Some('⠹')).contains('⠹'));
        assert!(rows[session].line(Some('⠹')).contains('⠹'));
        // Settled output carries no spinner column content at all.
        assert!(!rows[session].line(None).contains('⠹'));
    }

    #[test]
    fn off_a_terminal_each_row_prints_once_as_it_settles() {
        let mut progress = ProbeProgress {
            tty: false,
            drawn: 0,
            emitted: 0,
            frame: 0,
            header: true,
        };
        let running = stage_rows(&running_report());
        let first = progress.settled_since(&running);
        // bloom, discovery with its two attempt lines, then path.
        assert_eq!(first.len(), 5, "settled block: {first:?}");
        assert!(first[0].starts_with("bloom"));
        assert!(first[1].starts_with("discovery"));
        assert!(first[2].trim_start().starts_with("attempt 1"));
        assert!(first[3].trim_start().starts_with("attempt 2"));
        assert!(first[4].starts_with("path"));

        // A second poll with nothing new settled emits nothing.
        assert!(progress.settled_since(&running).is_empty());

        let mut done = running_report();
        done["session"] = serde_json::json!({"verdict": "ok", "reason": null,
                                             "elapsed_ms": 1000});
        done["rtt"] = serde_json::json!({"verdict": "ok", "reason": null, "elapsed_ms": 1000,
                                         "rtt_ms": 18, "reports_seen": 1});
        let rest = progress.settled_since(&stage_rows(&done));
        assert_eq!(rest.len(), 2, "session and rtt settled: {rest:?}");
        assert!(rest[0].starts_with("session"));
        assert!(rest[1].starts_with("rtt"));
        assert_eq!(progress.emitted, 5);
    }

    /// A four-hop shape: two up to the root, two back down.
    fn crossing_path() -> serde_json::Value {
        serde_json::json!({
            "our_coords": ["423877f900000000000000000000aaaa",
                           "a23598d900000000000000000000bbbb",
                           "00001a8c00000000000000000000cccc"],
            "their_coords": ["4f9b4a8400000000000000000000dddd",
                             "4d8009df00000000000000000000eeee",
                             "00001a8c00000000000000000000cccc"],
            "lca": "00001a8c00000000000000000000cccc",
        })
    }

    #[test]
    fn the_walk_runs_from_self_up_through_the_ancestor_and_down_to_the_target() {
        assert_eq!(
            walk_line(&crossing_path(), "00001a8c00000000000000000000cccc", false),
            "423877f9 [self] > a23598d9 > 00001a8c > 4d8009df > 4f9b4a84 [target]"
        );
    }

    #[test]
    fn a_target_that_is_itself_the_ancestor_ends_the_walk_on_it() {
        // Our parent is the target, so there is nothing to descend and the
        // ancestor and the target are the same address.
        let path = serde_json::json!({
            "our_coords": ["423877f900000000000000000000aaaa",
                           "a23598d900000000000000000000bbbb",
                           "00001a8c00000000000000000000cccc"],
            "their_coords": ["a23598d900000000000000000000bbbb",
                             "00001a8c00000000000000000000cccc"],
            "lca": "a23598d900000000000000000000bbbb",
        });
        assert_eq!(
            walk_line(&path, "a23598d900000000000000000000bbbb", false),
            "423877f9 [self] > a23598d9 [target]"
        );
    }

    #[test]
    fn the_ancestor_is_emphasised_on_a_terminal_and_nowhere_else() {
        let lca = "00001a8c00000000000000000000cccc";
        let plain = walk_line(&crossing_path(), lca, false);
        let styled = walk_line(&crossing_path(), lca, true);
        assert!(
            !plain.contains('\x1b'),
            "piped output carried escapes: {plain}"
        );
        assert!(styled.contains("\x1b[1m00001a8c\x1b[0m"), "{styled}");
        assert_eq!(
            styled.replace("\x1b[1m", "").replace("\x1b[0m", ""),
            plain,
            "the two must differ only by the emphasis"
        );
    }

    #[test]
    fn clipping_a_live_row_counts_characters_not_bytes() {
        // A display name arrives from the far side of the mesh, so the clip
        // has to survive multi-byte input rather than panic on a byte index.
        let line = format!("session   ok       {}", "é".repeat(200));
        let clipped = clip(&line, LIVE_WIDTH);
        assert_eq!(clipped.chars().count(), LIVE_WIDTH);
        assert!(clipped.ends_with('…'));
        assert_eq!(clip("short", LIVE_WIDTH), "short");
    }

    #[test]
    fn renders_a_depth_zero_coordinate_as_root() {
        let coords = serde_json::json!(["91b40c6e00000000000000000000beef"]);
        assert_eq!(render_coords(&coords, "self"), "91b40c6e [root]");
    }

    #[test]
    fn detects_bare_ula_literal() {
        assert!(is_fips_mesh_address("fd9d:abcd::1"));
        assert!(is_fips_mesh_address("fd00::"));
        assert!(is_fips_mesh_address(
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        ));
    }

    #[test]
    fn detects_bracketed_ula_with_port() {
        assert!(is_fips_mesh_address("[fd9d:abcd::1]:2121"));
        assert!(is_fips_mesh_address("[fd00::1]:8443"));
    }

    #[test]
    fn detects_bare_ula_with_port() {
        assert!(is_fips_mesh_address("fd9d:abcd::1:2121"));
    }

    #[test]
    fn rejects_non_ula_ipv6() {
        // fc00::/7 other half (fcXX:) is also ULA but not fd00::/8 — we only
        // block the fd-prefixed half that FIPS actually uses.
        assert!(!is_fips_mesh_address("fc00::1"));
        assert!(!is_fips_mesh_address("::1"));
        assert!(!is_fips_mesh_address("2001:db8::1"));
        assert!(!is_fips_mesh_address("[2001:db8::1]:2121"));
    }

    #[test]
    fn ignores_ipv4_and_hostnames() {
        assert!(!is_fips_mesh_address("192.0.2.1:2121"));
        assert!(!is_fips_mesh_address("peer.example.com:2121"));
        assert!(!is_fips_mesh_address("coinos.pro:2121"));
    }

    #[test]
    fn validates_only_target_transports() {
        assert!(validate_connect_address("fd9d::1:2121", "udp").is_err());
        assert!(validate_connect_address("fd9d::1:2121", "tcp").is_err());
        assert!(validate_connect_address("fd9d::1:2121", "ethernet").is_err());
        // Other transports are not inspected — they may legitimately accept
        // non-IP endpoints (tor onion, etc.).
        assert!(validate_connect_address("fd9d::1:2121", "tor").is_ok());
    }

    #[test]
    fn allows_valid_endpoints() {
        assert!(validate_connect_address("192.0.2.1:2121", "udp").is_ok());
        assert!(validate_connect_address("peer.example.com:2121", "tcp").is_ok());
        assert!(validate_connect_address("[2001:db8::1]:2121", "udp").is_ok());
    }
}
