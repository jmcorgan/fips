//! fipsctl — FIPS control client
//!
//! Connects to the FIPS daemon's Unix domain control socket, sends
//! commands, and pretty-prints the JSON response.

use clap::{Parser, Subcommand};
use fips::config::{write_key_file, write_pub_file};
use fips::upper::hosts::HostMap;
use fips::version;
use fips::{Identity, encode_nsec};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
    /// Generate a new FIPS identity keypair
    Keygen {
        /// Output directory for fips.key and fips.pub
        #[arg(short = 'd', long = "dir", default_value = "/etc/fips")]
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
        }
    }
}

/// Determine the default socket path.
///
/// Checks the system-wide path first (used when the daemon runs as a
/// systemd service), then falls back to the user's XDG runtime directory.
/// Uses directory existence rather than socket file existence so the check
/// works even when the user lacks traverse permission on /run/fips/ (0750).
fn default_socket_path() -> PathBuf {
    if Path::new("/run/fips").exists() {
        PathBuf::from("/run/fips/control.sock")
    } else if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(format!("{runtime_dir}/fips/control.sock"))
    } else {
        PathBuf::from("/tmp/fips-control.sock")
    }
}

/// Send a JSON request to the control socket and return the response.
fn send_request(socket_path: &Path, request_json: &str) -> Result<serde_json::Value, String> {
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

/// Resolve a peer identifier to an npub.
///
/// If the identifier starts with "npub1", it's returned as-is.
/// Otherwise, it's looked up as a hostname in /etc/fips/hosts.
fn resolve_peer(peer: &str) -> String {
    if peer.starts_with("npub1") {
        return peer.to_string();
    }

    let hosts = HostMap::load_hosts_file(Path::new(fips::upper::hosts::DEFAULT_HOSTS_PATH));
    match hosts.lookup_npub(peer) {
        Some(npub) => npub.to_string(),
        None => {
            eprintln!("error: unknown host '{peer}'");
            eprintln!("Not found in /etc/fips/hosts and not an npub.");
            std::process::exit(1);
        }
    }
}

fn main() {
    let cli = Cli::parse();

    // Commands that don't require a running daemon
    if let Commands::Keygen { dir, force, stdout } = &cli.command {
        let identity = Identity::generate();
        let nsec = encode_nsec(&identity.keypair().secret_key());
        let npub = identity.npub();

        if *stdout {
            println!("{nsec}");
            println!("{npub}");
            return;
        }

        let key_path = dir.join("fips.key");
        let pub_path = dir.join("fips.pub");

        if key_path.exists() && !force {
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

        if let Err(e) = write_pub_file(&pub_path, &npub) {
            eprintln!("error: failed to write pub file: {e}");
            std::process::exit(1);
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
        Commands::Connect {
            peer,
            address,
            transport,
        } => {
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
        Commands::Keygen { .. } => unreachable!(),
    };

    match send_request(&socket_path, &request) {
        Ok(value) => print_response(&value),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
