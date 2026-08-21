# Serve Many Peers on One Thread

**Goal:** handle every native datagram API flow from a single `poll` loop,
instead of dedicating a thread to each peer.

The straightforward listening program spawns a thread per flow. That is fine for
a handful of peers and wrong at the node's ceiling of 256, where it costs 256
threads mostly parked in `recv`.

Every object on this surface is a descriptor, so there is nothing to integrate:
both types implement `AsFd` and `AsRawFd` and go straight into a `poll`,
`select` or `epoll` set. **A listener is readable exactly when `accept` would not
block**, which is the property the whole shape rests on, and the crate asserts it
as a test rather than claiming it.

Read [use-the-native-datagram-api.md](use-the-native-datagram-api.md) first if
you have not opened a flow before.

## The whole program

One dependency beyond the crate, `libc`, for `poll` itself:

```toml
[dependencies]
fips = { git = "https://github.com/jmcorgan/fips" }
libc = "0.2"
```

```rust
//! Serve many flows from one poll loop, with no thread per peer.
//!
//! ```text
//! eventloop /run/fips/api.sock 4242
//! ```

use fips::native::client::{FipsListener, FipsStream};
use std::env;
use std::error::Error;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

/// How long a flow may go without a datagram before this program closes it.
///
/// Nothing else will end one. The wire carries no far-end close, so a peer that
/// has stopped sending is indistinguishable from one that is thinking, and a
/// reactor with no deadline holds every flow it ever accepted until it exits.
const IDLE: Duration = Duration::from_secs(30);

/// Hold the port named on the command line and serve every flow from one loop.
fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let (Some(socket), Some(port)) = (args.next(), args.next()) else {
        return Err("usage: eventloop <socket-path> <local-port>".into());
    };
    let port: u16 = port.parse()?;

    let listener = FipsListener::bind_at(Path::new(&socket), port)?;
    println!("holding {}", listener.local_addr());

    // Each flow with the time its last datagram arrived, which is what the
    // deadline is measured against.
    let mut flows: Vec<(FipsStream, Instant)> = Vec::new();
    loop {
        let mut fds = vec![watch(listener.as_raw_fd())];
        fds.extend(flows.iter().map(|(flow, _)| watch(flow.as_raw_fd())));

        let count = fds.len() as libc::nfds_t;
        // The timeout is what makes the deadline reachable: with no events at
        // all the loop must still wake to notice a flow that has gone quiet.
        let timeout = IDLE.as_millis() as libc::c_int;
        // SAFETY: `fds` is a live slice of `pollfd` for the whole call, and
        // `count` is its length.
        if unsafe { libc::poll(fds.as_mut_ptr(), count, timeout) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        // The established flows first, and backwards: removing a closed one
        // must not renumber one not yet examined, and accepting below would
        // otherwise push a flow this pass has no `revents` for. The listener
        // occupies slot 0, hence the offset.
        let now = Instant::now();
        for index in (0..flows.len()).rev() {
            if ready(&fds[index + 1]) {
                if echo(&flows[index].0) {
                    flows[index].1 = now;
                } else {
                    flows.remove(index); // dropping it releases the flow
                }
            } else if now.duration_since(flows[index].1) >= IDLE {
                println!("closing an idle flow from {}", flows[index].0.peer_addr());
                flows.remove(index);
            }
        }

        // Once per readiness rather than in a loop: the descriptor is blocking,
        // so a second `accept` with nothing queued would stall the whole loop.
        if ready(&fds[0]) {
            let (flow, peer) = listener.accept()?;
            println!("flow from {peer}");
            flows.push((flow, now));
        }
    }
}

/// A `pollfd` asking for readability on `fd`.
///
/// `POLLHUP` needs no asking for: it is reported in `revents` whether or not
/// it was requested, which is what lets one mask serve both cases.
fn watch(fd: RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// Whether this descriptor has something to read or has hung up.
fn ready(poll: &libc::pollfd) -> bool {
    poll.revents & (libc::POLLIN | libc::POLLHUP) != 0
}

/// Return one datagram, reporting whether the flow is still usable.
fn echo(flow: &FipsStream) -> bool {
    let mut buf = vec![0u8; flow.max_payload()];
    match flow.recv(&mut buf) {
        // `Ok(0)` is an empty datagram and not a close, so it is echoed like
        // any other. `EPIPE` is the daemon gone: no peer can close a flow.
        Ok(len) => flow.send(&buf[..len]).is_ok(),
        Err(_) => false,
    }
}

/// Report a failure on stderr and exit non-zero.
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("eventloop: {error}");
            ExitCode::FAILURE
        }
    }
}
```

## The four rules

**Register the listener for readability only.** There is nothing else to ask it
for, and `POLLHUP` arrives in `revents` whether or not it was requested.

**Accept once per readiness, not in a loop.** The descriptor is blocking, so a
second `accept` with nothing queued stalls the whole loop. Looping until
`WouldBlock` is correct only after `listener.set_nonblocking(true)`, which is
also what an edge-triggered `epoll` requires.

**Give every flow a deadline, and the poll a timeout that makes the deadline
reachable.** This is the most important of the four. Nothing will tell a reactor
that a peer is finished, so a flow that goes quiet stays in the poll set for ever
unless the program removes it — and with no events at all the loop must still
wake in order to notice. **A reactor with a deadline but no poll timeout has a
deadline it can never reach.**

**A flow from `accept` arrives blocking, whatever the listener was set to.**
They are separate sockets and the daemon hands over a fresh one. The program
above deliberately leaves them blocking and makes exactly one `recv` per
readiness, which is safe on a blocking descriptor and is why it needs no flags at
all. If you want them otherwise, call `set_nonblocking` on the flow.

## Where this reaches past the client module

This program needs `libc` and an `unsafe` block, and it is the only one of the
API's example programs that needs anything.

That is a narrower gap than it once was. Readiness and a bounded wait were both
missing from the surface; `set_nonblocking` closed the first and
`set_read_timeout` the second, and a program wanting an option on a flow now has
a method for it. What is left is a different kind of thing: **an option on a flow
is something a surface can supply, and a reactor's own polling mechanism is
not.** No surface that stops at the descriptor can supply `poll`.

`AsRawFd` rather than `AsFd` here is deliberate: `libc::poll` takes a raw
descriptor. Prefer `AsFd` anywhere you **hold** a registration, because its
borrow cannot outlive the stream; this loop rebuilds its `pollfd` set from live
references on every pass, so it holds nothing across an iteration.

## See also

- [use-the-native-datagram-api.md](use-the-native-datagram-api.md) — opening
  flows and receiving them, and the traps that apply to any program here
- [write-a-native-api-client.md](write-a-native-api-client.md) — the same loop
  in a language with no client library
- [../reference/native-api.md](../reference/native-api.md#fipslistener) — what
  `accept`, `incoming` and `set_nonblocking` guarantee
- [../reference/native-api.md](../reference/native-api.md#what-a-daemon-restart-costs)
  — what a reactor sees when the daemon goes away
