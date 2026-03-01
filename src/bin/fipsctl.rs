//! fipsctl — FIPS control client
//!
//! Connects to the FIPS daemon's Unix domain control socket, sends a
//! query command, and pretty-prints the JSON response.

use clap::{Parser, Subcommand};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// FIPS control client
#[derive(Parser, Debug)]
#[command(name = "fipsctl", version, about = "Query a running FIPS daemon")]
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
fn default_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(format!("{runtime_dir}/fips/control.sock"))
    } else if Path::new("/run/fips/control.sock").exists() {
        PathBuf::from("/run/fips/control.sock")
    } else {
        PathBuf::from("/tmp/fips-control.sock")
    }
}

fn main() {
    let cli = Cli::parse();

    let socket_path = cli.socket.unwrap_or_else(default_socket_path);
    let command_name = match &cli.command {
        Commands::Show { what } => what.command_name(),
    };

    // Connect to the control socket
    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "error: cannot connect to {}: {}",
                socket_path.display(),
                e
            );
            eprintln!("Is the FIPS daemon running?");
            std::process::exit(1);
        }
    };

    // Set timeouts
    let timeout = Duration::from_secs(2);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    // Send request
    let request = format!("{{\"command\":\"{}\"}}\n", command_name);
    if let Err(e) = stream.write_all(request.as_bytes()) {
        eprintln!("error: failed to send request: {}", e);
        std::process::exit(1);
    }

    // Shutdown write half to signal end of request
    let _ = stream.shutdown(std::net::Shutdown::Write);

    // Read response
    let reader = BufReader::new(&stream);
    let response_line = match reader.lines().next() {
        Some(Ok(line)) => line,
        Some(Err(e)) => {
            eprintln!("error: failed to read response: {}", e);
            std::process::exit(1);
        }
        None => {
            eprintln!("error: no response from daemon");
            std::process::exit(1);
        }
    };

    // Parse and pretty-print
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&response_line) else {
        // Not JSON, print raw
        println!("{}", response_line);
        return;
    };

    let status = value
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    if status == "error" {
        let msg = value
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        eprintln!("error: {}", msg);
        std::process::exit(1);
    }

    // Pretty-print the data field (or whole response if no data field)
    let output = if let Some(data) = value.get("data") {
        serde_json::to_string_pretty(data).unwrap_or(response_line)
    } else {
        serde_json::to_string_pretty(&value).unwrap_or(response_line)
    };
    println!("{}", output);
}
