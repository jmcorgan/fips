# Use the Native Datagram API

**Experimental.** The native datagram API lets a local program send
and receive datagrams addressed by pubkey and FSP port, with no IPv6
emulation and no TUN device in the path. A client connects to a Unix
socket, opens a flow to a remote pubkey, and is handed a file
descriptor it reads and writes datagrams on.

It is not a stable API surface, not a reliability layer, and not the
v2 external process API. No compatibility promise is made: the socket
protocol, the Rust client, and the configuration keys may change or be
withdrawn in any release. It is built on Linux, FreeBSD and macOS only.

**The macOS build is exercised less than the others, and you should know
by how much.** The socket type differs there: macOS has no
`SOCK_SEQPACKET` for `AF_UNIX`, so a flow descriptor is a `SOCK_DGRAM`
socket, which keeps message boundaries just the same but reports a
closed peer differently. The unit tests run on macOS in the project's
own automation and pass in full. The end-to-end suite does not: it
drives a client container against a node container over a shared
volume, and that arrangement is Linux only. So on macOS the socket
lifecycle, the descriptor hand-off across a process boundary, and the
reclaiming of a port when a client exits are covered by unit tests
rather than by anything that runs the daemon and a client as two real
processes.

That is a gap in testing, not a known defect. It is written here
because you are the one who would meet it first.

Before enabling it, read the security posture below. It is short and
it is the whole of the access control.

## Before you start: what enabling this grants

The API socket is mode `0770` owned by group `fips`, the same group as
the control socket, and that is the entire authorization model.

**Any user in the `fips` group can impersonate the node on the mesh.**
A process that can open the socket can send datagrams under this
node's identity to any peer it names, and can hold a port and receive
mesh traffic addressed to this node. Peers authenticate those
datagrams as coming from this node, because they did.

On a node with the API enabled, treat `fips` group membership exactly
as you would treat `/etc/fips/fips.key`. If the group has been handed
out so that people can run `fipsctl`, enabling the API upgrades every
one of those accounts from "can read node state" to "can speak as the
node". See
[../reference/security.md](../reference/security.md#native-datagram-api).

The API is disabled by default, and nothing in the packaging turns it
on.

## Step 1: Enable it on the daemon

Add to `/etc/fips/fips.yaml`:

```yaml
node:
  native_api:
    enabled: true
```

Every other key has a working default; see
[../reference/configuration.md](../reference/configuration.md#native-datagram-api-nodenative_api)
for the full list, including the flow ceiling and the per-flow queue
depth.
Leave `debug_commands` alone — it is off by default and belongs to the
test harness.

Restart the daemon and confirm the socket came up:

```sh
sudo systemctl restart fips
sudo journalctl -u fips | grep 'Native API socket listening'
```

The log line carries the path the daemon resolved, normally
`/run/fips/api.sock`.

## Step 2: Link the crate

The client is a module of the `fips` crate itself, so a program links
the crate and uses `fips::native::client`:

```toml
[dependencies]
fips = { git = "https://github.com/jmcorgan/fips" }
```

A checkout on the same machine can use a path dependency instead:

```toml
[dependencies]
fips = { path = "../fips" }
```

The client is blocking and std-only. It brings no async runtime, so a
plain `fn main` is enough, and a program using it does not need
`serde_json`, `libc`, or any knowledge of the socket's line protocol.

## Step 3: Open a flow and exchange datagrams

The surface is shaped like `std::net`: `FipsStream::connect` opens a
flow the way `TcpStream::connect` opens a connection, and the stream it
returns carries the datagrams.

An address is a public key and a port. The npub is that key written
down, and converting between the two is bech32 and nothing else: no
lookup, no resolution, no name service. So `("npub1...", 4600)` and
`"npub1...:4600"` name the same address, and one parameter takes either,
exactly as `ToSocketAddrs` does:

```rust
use fips::native::client::FipsStream;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let flow = FipsStream::connect(("npub1...", 4600))?;

    flow.send(b"hello")?;

    // Nothing tells you a peer is never going to answer, so bound the
    // wait yourself. Without this the recv below blocks for ever
    // against a peer that is offline or listening elsewhere.
    flow.set_read_timeout(Some(Duration::from_secs(5)))?;

    // Size the buffer at the flow's own limit so no datagram it can
    // carry is truncated on the way in.
    let mut buf = vec![0u8; flow.max_payload()];
    let len = flow.recv(&mut buf)?;
    println!("{len} bytes back from {}", flow.peer_addr());
    Ok(())
}
```

**`connect` contacts no peer.** It is a local registration at the
daemon, and nothing about it proves the peer exists, is reachable, or is
listening. The Berkeley shape invites the opposite reading, which is why
it is said here as well as in the API documentation.

`FipsStream::max_payload` is the daemon's answer for that flow: the
transport MTU less the FIPS encapsulation and the four-byte port header.
`FipsStream::send` refuses anything larger locally rather than letting it
be dropped further along.

`connect` uses the packaged socket path, `/run/fips/api.sock`, and an
ephemeral local port from 49152 upward. Use `connect_from(port, addr)`
when the local port matters, such as when the far end has been told it in
advance, and `connect_at(path, port, addr)` when the daemon's socket is
somewhere else.

**Bounding a wait.** `set_read_timeout` and `set_write_timeout` bound one
`recv` or one `send`, as their `TcpStream` counterparts do, and
`read_timeout` and `write_timeout` read them back. An expiring deadline
reports `WouldBlock`. `None` clears a deadline; a zero duration is
refused with `EINVAL`, because the kernel reads a zero timeout as "wait
for ever" and a caller passing zero means the opposite.

## Step 4: Receive flows from peers

`FipsListener::bind` holds a port, and `accept` blocks until a flow
arrives on it. `incoming()` is the same thing as an iterator, as it is on
`TcpListener`:

```rust
use fips::native::client::FipsListener;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = FipsListener::bind(4600)?;
    println!("holding {}", listener.local_addr());

    for arrival in listener.incoming() {
        let flow = arrival?;
        std::thread::spawn(move || {
            let mut buf = vec![0u8; flow.max_payload()];
            if let Ok(len) = flow.recv(&mut buf) {
                let _ = flow.send(&buf[..len]);
            }
        });
    }
    Ok(())
}
```

`bind(0)` asks the daemon to pick the port, and `local_addr()` reports
the one it actually held: `getsockname` after `bind(2)` with port 0. Use
`bind_at(path, port)` when the daemon's socket is somewhere else. A
program wanting two independent accept loops binds two listeners.

The thread above serves **one datagram and then drops the flow**. That is
deliberate, and the fourth note below says why.

An accepted flow's `peer_addr()` names the far end by npub and port,
because the key is the address and it is the one that peer's session
authenticated. The 16-byte node address that travels on the wire is a
truncated hash of that key; it does not invert, and it appears nowhere on
this surface.

Both types implement `AsFd` and `AsRawFd`, which is the point of the
listener being a descriptor: it is readable exactly when `accept` would
not block, so a program with its own `poll`, `select` or `epoll` loop adds
it to that loop rather than dedicating a thread to blocking in `accept`.
**Prefer `AsFd`**: its borrow cannot outlive the stream, so a reactor
cannot hold a registration for a descriptor that has since been closed and
its number reissued to the next `connect`.

`set_nonblocking(true)` on either type turns a blocking call into
`WouldBlock`, which is the other way to drive a reactor. **A flow from
`accept` is blocking however its listener was set**: they are separate
sockets, so set it on the flow if the flow is what you poll.

## Four things that will bite you

**Setup leaves you nothing to keep alive.** `connect` and `bind` each
open a connection to the daemon socket, send one command, take the
descriptor off the reply and close that connection before returning. What
you hold afterwards is that descriptor and plain copies of what the reply
said, so a `FipsStream` and a `FipsListener` are `Send` and `'static`,
borrow nothing, and outlive nothing. A flow lasts exactly as long as its
own descriptor.

**Dropping a stream is how you close it.** There is no close command.
The daemon watches the descriptor and releases the flow and its port
when it goes away. Dropping a listener unbinds its port the same way, and
leaves the flows already accepted from it untouched. A program that parks
streams in a `Vec` and never removes them holds ports and flow slots
exactly as if it had leaked descriptors.

**Nothing peer-driven ever ends a flow, so your program has to.** The v1
wire carries no half-close. Nothing closes the daemon's half of a live
accepted flow, so a loop written as "echo until the flow closes", or one
that breaks on `POLLHUP`, waits for a signal that cannot arrive. The
mistake compiles, reads naturally, and passes every test that does not
involve a real daemon. What it costs is one blocked thread and one held
flow per peer, until the process dies; the node reaches its ceiling of 256
flows one silent peer at a time, and after that every `connect` on that
node, from any program, returns `EMFILE`.

Two shapes are correct, and a program that receives at all needs both.
**One exchange per flow** decides how many datagrams a flow carries, so
its end is decided rather than waited for. **A deadline you impose
yourself** — `set_read_timeout`, or a poll timeout in a reactor — bounds
a wait on a peer that may never speak again. The first decides when you
have said enough; the second decides when you have waited long enough.
A longer conversation needs an end-of-conversation marker in the payload,
because the protocol will not supply one.

Two signals are **not** a close. `Ok(0)` from `recv` is an empty datagram
and only that, so do not write `if n == 0 { break }` out of TCP habit.
`EPIPE` is real, and means the daemon went away — never that a peer
finished.

**Ports below 1024 are refused.** 0 through 255 are reserved for
protocol use and 256 through 1023 for FIPS standard services, the IPv6
shim among them. A client may hold 1024 through 65535. The refusal
applies to the remote port too, so a peer listening below 1024 is
unreachable from here.

## Step 5: Run the worked example

`examples/native-echo.rs` in the source tree is an echo server built
on nothing but this client. It holds a port and returns each datagram
to whoever sent it:

```sh
cargo run --example native-echo -- /run/fips/api.sock 4600
```

It prints `native-echo: holding port 4600` once the port is held, then
a line per datagram returned. It serves one datagram per flow by
design, for the reason the third note above gives.

## Step 6: Inspect what the node is holding

```sh
fipsctl show native-flows
```

This reports every flow the node holds — established and pending
accept — with its ports, its queue depth and its age, every bound
listener with its backlog, and the `native` counter family. The
counters are also in `fipsctl stats metrics` under `native`, where the
`drop_*` fields separate a datagram refused for having no listening
port from one dropped because a client was not reading fast enough.
For the response shape, see
[../reference/control-socket.md](../reference/control-socket.md#read-only-queries).

Reach for this when datagrams go missing. **Four places lose data with
nothing reported to your program**: a full per-flow queue, a listener that
does not accept fast enough, an outbound datagram sent before a session
exists, and an outbound datagram after the transport MTU has fallen.
[../reference/native-api.md](../reference/native-api.md#where-data-disappears)
describes each and what bounds it.

## See also

- [../reference/native-api.md](../reference/native-api.md)
  — the whole surface: every type and method, the errno table, the
  ceilings, the line protocol and the command reference
- [write-a-native-api-client.md](write-a-native-api-client.md)
  — speaking the line protocol directly from another language
- [serve-many-peers-on-one-thread.md](serve-many-peers-on-one-thread.md)
  — one `poll` loop instead of the thread per flow this guide spawns
- [../design/fips-native-api.md](../design/fips-native-api.md)
  — why this exists beside the TUN path, and what it is not
- [../reference/configuration.md](../reference/configuration.md#native-datagram-api-nodenative_api)
  — every `node.native_api.*` key and its default
- [../reference/security.md](../reference/security.md#native-datagram-api)
  — what `fips` group membership grants once the API is on
- [../reference/control-socket.md](../reference/control-socket.md)
  — the `show_native_flows` response shape
- [../reference/cli-fipsctl.md](../reference/cli-fipsctl.md)
  — `fipsctl show native-flows`
