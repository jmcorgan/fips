# Native Datagram API Walkthrough

A side trip. You will run two FIPS nodes on one machine, write a listening
program and a connecting program against the native datagram API, and watch one
datagram cross between them. Then you will look at the flow from the outside
with `fipsctl` while it is still open.

Nothing here touches the public mesh, and nothing needs root. Both nodes run
with no TUN device and no DNS, peered directly over loopback UDP, so the whole
session lives in one scratch directory you delete at the end.

**This is not part of the numbered progression.** Take it any time. It assumes
you can build the daemon from source and can read Rust; it does not assume you
have worked through the tutorials.

**The API is experimental.** Names, fields and the command set may change
without a deprecation cycle. It is Linux, FreeBSD and macOS only.

## What you will end up with

- Two nodes, each with its own identity, control socket and API socket.
- A listening program that holds port 4600 and echoes one datagram per flow.
- A connecting program that opens a flow to the other node's public key and
  gets its datagram back.
- A reading of `fipsctl show native-flows` taken while the flow is open.

## Step 1: Build the daemon and its tools

From a checkout of the FIPS source:

```sh
cargo build --release --bins
```

That gives you `target/release/fips` and `target/release/fipsctl`. Put them on
your path for the rest of this walkthrough:

```sh
export PATH="$PWD/target/release:$PATH"
```

## Step 2: Make two identities

`keygen -s` prints a keypair to stdout and writes nothing:

```sh
fipsctl keygen -s
```

```text
nsec1...
npub1...
```

Run it twice and keep both pairs. Call them A and B. You need each node's
`nsec` for its own config, and each node's `npub` for the *other* node's peer
entry.

```sh
mkdir -p ~/napi-lab/a ~/napi-lab/b
cd ~/napi-lab
```

## Step 3: Write the two configs

Node A, at `~/napi-lab/a/fips.yaml`. Substitute A's `nsec` and B's `npub`:

```yaml
node:
  identity:
    nsec: "<A's nsec>"
  control:
    socket_path: "/home/YOU/napi-lab/a/control.sock"
  native_api:
    enabled: true
    socket_path: "/home/YOU/napi-lab/a/api.sock"

tun:
  enabled: false

dns:
  enabled: false

transports:
  udp:
    bind_addr: "127.0.0.1:2121"
    mtu: 1472

peers:
  - npub: "<B's npub>"
    alias: "node-b"
    addresses:
      - transport: udp
        addr: "127.0.0.1:2122"
```

Node B, at `~/napi-lab/b/fips.yaml`, is the mirror image: B's `nsec`, A's
`npub`, its own sockets under `b/`, `bind_addr` on `2122`, and its peer address
pointing at `2121`.

> **Use absolute paths.** The daemon does not resolve a socket path relative to
> the config file. Putting an `nsec` in a config is fine for a throwaway lab
> node like this one; for anything you keep, use
> [../how-to/persistent-identity.md](../how-to/persistent-identity.md) instead.

Disabling TUN and DNS is what lets both nodes run as your own user. A node with
a TUN device needs `CAP_NET_ADMIN`, and this walkthrough does not need one:
the native API is the path that does not go through the IPv6 adapter.

## Step 4: Start both nodes

In two terminals:

```sh
fips --config ~/napi-lab/a/fips.yaml
```

```sh
fips --config ~/napi-lab/b/fips.yaml
```

Each should log that it bound its API socket:

```text
Native API socket listening path=/home/YOU/napi-lab/a/api.sock
```

In a third terminal, confirm the two found each other:

```sh
fipsctl -s ~/napi-lab/a/control.sock show peers
```

Wait for B to appear with a session. The link forms over loopback UDP and
usually takes a second or two. **Wait for it before going on**: a `connect` on
a flow contacts no peer, so it will succeed whether or not the link is up, and
the datagram would simply be held and then dropped.

## Step 5: Write the listening program

Make a crate inside the lab directory (the shell is still in
`~/napi-lab` from Step 2, so both crates land there and Step 8's
`rm -rf ~/napi-lab` removes them along with everything else):

```sh
cargo new --bin napi-listen
cd napi-listen
```

Point it at your FIPS checkout in `Cargo.toml`:

```toml
[dependencies]
fips = { path = "/path/to/your/fips/checkout" }
```

`src/main.rs`:

```rust
//! Hold a port and echo one datagram per flow.

use fips::native::client::{FipsListener, FipsStream};
use std::env;
use std::error::Error;
use std::path::Path;
use std::thread;

/// Return one datagram to where it came from, then release the flow.
fn serve(flow: FipsStream) {
    // Sized at the flow's own limit, so no datagram it can carry is
    // truncated on the way in and echoed short.
    let mut buf = vec![0u8; flow.max_payload()];
    match flow.recv(&mut buf) {
        Ok(len) => {
            let _ = flow.send(&buf[..len]);
            println!("returned {len} bytes to {}", flow.peer_addr());
        }
        Err(error) => eprintln!("receiving: {error}"),
    }
    // Returning drops the flow, which closes its descriptor. That is what
    // releases the flow at the daemon; there is no close call to make.
}

fn main() -> Result<(), Box<dyn Error>> {
    let socket = env::args().nth(1).ok_or("usage: napi-listen <api-socket>")?;
    let listener = FipsListener::bind_at(Path::new(&socket), 4600)?;
    println!("holding {}", listener.local_addr());

    for arrival in listener.incoming() {
        // Detached rather than joined: the accept loop must not wait on one
        // peer, and the thread owns everything it touches.
        match arrival {
            Ok(flow) => drop(thread::spawn(move || serve(flow))),
            Err(error) => eprintln!("accepting: {error}"),
        }
    }
    Ok(())
}
```

Run it against node B:

```sh
cargo run -- ~/napi-lab/b/api.sock
```

```text
holding npub1...:4600
```

**Note what `serve` does not do.** It does not loop reading until the flow
closes. The v1 wire carries no half-close, so nothing peer-driven would ever
end that loop; it would hold a thread and a flow slot per peer until the
process died. One exchange per flow is the program's own decision, and making
it is mandatory. See
[../how-to/use-the-native-datagram-api.md](../how-to/use-the-native-datagram-api.md#four-things-that-will-bite-you).

**Note also what `incoming()` does not do.** It never returns `None`, and a
failed accept arrives as an `Err` item rather than ending the iteration. Writing
`let flow = arrival?;` here would exit the loop on the first transient error,
which is a different shape from `TcpListener` habits.

## Step 6: Write the connecting program

```sh
cd ..
cargo new --bin napi-connect
cd napi-connect
```

Same dependency line. `src/main.rs`:

```rust
//! Open a flow to a peer, exchange one datagram, and exit.

use fips::native::client::FipsStream;
use std::env;
use std::error::Error;
use std::io;
use std::path::Path;
use std::time::Duration;

/// How long to wait for the peer's answer before giving up on it.
const REPLY: Duration = Duration::from_secs(10);

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let (Some(socket), Some(peer)) = (args.next(), args.next()) else {
        return Err("usage: napi-connect <api-socket> <peer-npub>".into());
    };

    // One setup call, and it contacts no peer: the daemon registers the flow
    // locally and hands back the descriptor it rides on. Success here says
    // nothing about the peer existing, being reachable, or listening.
    let flow = FipsStream::connect_at(Path::new(&socket), 0, (peer, 4600))?;
    println!("{} -> {}", flow.local_addr(), flow.peer_addr());

    // Before the first recv and not after it, because the peer may never
    // answer at all and the deadline is what makes that a failure rather
    // than a hang.
    flow.set_read_timeout(Some(REPLY))?;

    flow.send(b"hello")?;

    let mut buf = vec![0u8; flow.max_payload()];
    match flow.recv(&mut buf) {
        Ok(len) => println!("{}", String::from_utf8_lossy(&buf[..len])),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            return Err(format!("no answer from {} in {REPLY:?}", flow.peer_addr()).into());
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
```

Run it against node A, naming node B's npub:

```sh
cargo run -- ~/napi-lab/a/api.sock <B's npub>
```

```text
npub1...:49152 -> npub1...:4600
hello
```

The listener's terminal reports the other half:

```text
returned 5 bytes to npub1...:49152
```

That datagram went from your connecting program, into node A over a Unix
socket, across loopback UDP inside an encrypted FSP session, into node B, and
out to your listening program on another Unix socket. No IPv6 address and no
TUN device was involved anywhere in it.

## Step 7: Watch a flow from the outside

The exchange above is over in milliseconds. To look at a live flow, make the
connector hold one open: add a `std::thread::sleep(Duration::from_secs(60));`
before the final `Ok(())` and run it again.

While it sleeps:

```sh
fipsctl -s ~/napi-lab/b/control.sock show native-flows
```

You get every flow node B holds, with its ports, its queue depth and its age,
plus every bound listener and its backlog. The counters are in:

```sh
fipsctl -s ~/napi-lab/b/control.sock stats metrics
```

under `native`, where the `drop_*` fields separate a datagram refused for
having no listening port from one dropped because a client was not reading fast
enough. Those counters are the only way to see a drop: **nothing on the API
surface reports one to your program.**

## Step 8: Clean up

Stop both daemons with Ctrl-C, then:

```sh
rm -rf ~/napi-lab
```

The identities were only ever in those config files, so removing the directory
removes them. Nothing was written outside it and nothing was published to any
relay.

## Where to go next

- [../how-to/use-the-native-datagram-api.md](../how-to/use-the-native-datagram-api.md)
  — the same ground as a recipe, including enabling the API on a real node and
  the security posture that granting a program access to the socket implies
- [../reference/native-api.md](../reference/native-api.md)
  — every type and method, the errno table, the ceilings, and what happens to
  data that disappears
- [../how-to/write-a-native-api-client.md](../how-to/write-a-native-api-client.md)
  — doing all of this from C, Python or Go, where there is no client library
  and the obligations become yours
