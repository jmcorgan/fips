//! An echo server on the native datagram API, and the reference client for it.
//!
//! Run it beside a daemon whose native API socket is the first argument; it
//! holds the port given as the second and returns every datagram sent to that
//! port to whoever sent it.
//!
//! ```text
//! native-echo /run/fips/api.sock 4600
//! ```
//!
//! **One exchange, one flow.** A served flow takes a single datagram, sends it
//! back and closes. A datagram API carries no far-end close, so a server that
//! kept reading would hold the flow until its own process went away and would
//! be waiting for a signal that never comes; the accept loop takes the next
//! arrival instead.
//!
//! **It imports `fips::native::client` and nothing else from the crate.** That
//! is the point of the example as much as the echoing is: needing `serde_json`,
//! `libc`, or any knowledge of the line protocol here would mean the client
//! module had failed to hide something, and the fix would belong there.
//!
//! **Platform.** The client module is built on Linux and FreeBSD only, because
//! macOS has no `AF_UNIX` `SOCK_SEQPACKET` and Windows no `SCM_RIGHTS`. `main`
//! is gated to match rather than the file being Linux-only by accident:
//! `cargo clippy --all-targets` and `cargo nextest run` both compile example
//! targets, and both run on macOS, so an ungated file would break those runs
//! there instead of this program refusing to start.

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod echo {
    use fips::native::client::{FipsListener, FipsStream};
    use std::env;
    use std::io::{self, Write};
    use std::path::Path;
    use std::process::ExitCode;
    use std::thread;

    /// Hold the port named on the command line and echo what arrives on it.
    ///
    /// Returns only on failure: a healthy server has no reason to stop, and the
    /// caller kills it.
    pub fn run() -> ExitCode {
        let mut args = env::args().skip(1);
        let (Some(socket), Some(port)) = (args.next(), args.next()) else {
            eprintln!("usage: native-echo <socket-path> <local-port>");
            return ExitCode::FAILURE;
        };
        let port: u16 = match port.parse() {
            Ok(port) => port,
            Err(error) => {
                eprintln!("native-echo: {port:?} is not a port: {error}");
                return ExitCode::FAILURE;
            }
        };

        // "cannot hold" rather than "holding": a caller waits for the success
        // line below by substring, and a failure line containing it would
        // satisfy that wait and hide the reason.
        let listener = match FipsListener::bind_at(Path::new(&socket), port) {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("native-echo: cannot hold port {port} on {socket}: {error}");
                return ExitCode::FAILURE;
            }
        };

        // The port the daemon actually held, which is what a caller asking for
        // an ephemeral one needs. A caller waits on this line before it sends
        // anything, so it is flushed rather than left to the line buffer.
        println!("native-echo: holding port {}", listener.local_addr().port());
        let _ = io::stdout().flush();

        for arrival in listener.incoming() {
            match arrival {
                // Detached rather than joined: the accept loop must not wait on
                // one peer, and the thread owns everything it touches.
                Ok(flow) => drop(thread::spawn(move || serve(flow))),
                Err(error) => {
                    eprintln!("native-echo: accepting on port {port}: {error}");
                    return ExitCode::FAILURE;
                }
            }
        }
        // `incoming` has no end: a listener has no last flow. Reaching here at
        // all would mean the iterator broke its contract.
        ExitCode::FAILURE
    }

    /// Return one datagram to where it came from, then release the flow.
    ///
    /// Dropping the flow closes its descriptor, which is what tells the daemon
    /// the flow is finished; there is no close command to send.
    fn serve(flow: FipsStream) {
        // Sized at the flow's own limit, so no datagram the flow can carry is
        // truncated on the way in and echoed short.
        let mut buf = vec![0u8; flow.max_payload()];
        let len = match flow.recv(&mut buf) {
            Ok(len) => len,
            Err(error) => {
                eprintln!("native-echo: receiving from {}: {error}", flow.peer_addr());
                return;
            }
        };
        match flow.send(&buf[..len]) {
            Ok(()) => println!("native-echo: returned {len} bytes to {}", flow.peer_addr()),
            Err(error) => eprintln!("native-echo: returning to {}: {error}", flow.peer_addr()),
        }
        let _ = io::stdout().flush();
    }
}

/// Serve until killed.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn main() -> std::process::ExitCode {
    echo::run()
}

/// Refuse cleanly where the native API client is not built.
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "native-echo needs the native datagram API client, which is built on \
         Linux and FreeBSD only"
    );
    std::process::ExitCode::FAILURE
}
