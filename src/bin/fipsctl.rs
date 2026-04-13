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
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv6Addr, SocketAddrV6};
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
fn default_key_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/etc/fips")
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

#[cfg(test)]
mod tests {
    use super::*;

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
