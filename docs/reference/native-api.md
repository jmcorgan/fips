# Native Datagram API

The native datagram API lets a program send and receive datagrams over the
mesh addressed by public key and port, with no IPv6 emulation and no TUN
device. A program opens a flow to a peer, receives a socket descriptor, and
uses ordinary socket calls on it.

This document describes the surface. For the steps to enable it and write a
first program, see
[../how-to/use-the-native-datagram-api.md](../how-to/use-the-native-datagram-api.md).

**Status: experimental.** The Rust surface and the line protocol may both
change. The API is off by default and is Unix only.

## Enabling it

Every bound is a key under `node.native_api`. The defaults are the values
compiled into `src/config/node.rs`.

| Key | Default | What it bounds |
| --- | ------- | -------------- |
| `enabled` | `false` | Whether the socket is bound at all. |
| `socket_path` | resolved | See [Socket path](#socket-path). |
| `pending_per_flow` | `16` | Datagrams held for one flow, whether it awaits hand-off or its program is slow to read. Ceiling 64, floor 1, both applied when the configuration loads. |
| `backlog` | `16` | Flows announced on one listener and not yet taken. Floor 1. |
| `max_flows` | `256` | Flows this node holds at once, across every program. Established and pending flows both count. |
| `debug_commands` | `false` | Whether the three debug commands are answered. |

There is no cap on flows per program, and no notion of a program to hang one
on. One program can reach `max_flows` by itself, and the ceiling is shared
with every other program on that node.

See [configuration.md](configuration.md#native-datagram-api-nodenative_api)
for the full YAML reference, and [security.md](security.md#native-datagram-api)
for what `fips` group membership grants once the API is on.

## Socket path

`node.native_api.socket_path` has a default resolved at startup rather than a
fixed string. The resolver takes the first of these that applies and appends
`api.sock`:

1. `/run/fips/api.sock`, when `/run/fips` exists as a directory. This is the
   packaged Linux convention, and the constant the shipped Rust client compiles
   in on Linux.
2. `/var/run/fips/api.sock` on FreeBSD and macOS, whose service scripts and
   LaunchDaemons create that directory. Linux skips this step, and macOS has no
   `/run` for step 1 to find, so this is where a packaged macOS daemon lands and
   is the constant the client compiles in there.
3. `$XDG_RUNTIME_DIR/fips/api.sock`, when that variable names an existing
   directory. A development run usually gets this one.
4. `/tmp/fips-api.sock`, the last resort.

Selection is by existence of the directory, not by whether the client can
write to it. A client should therefore take the path as an argument with these
as its defaults, rather than compile one in.

## Addressing

An address is an x-only secp256k1 public key and a port. Nothing else
identifies an end. There is no node identifier, no address family, and no
scope.

The npub is the key written down. Conversion between the two is bech32 and
nothing else: no lookup, no resolution, no name service. The conversion is
local, needs no daemon, and fails identically whether or not one runs.

The 16-byte node address that the wire carries never appears on this surface.
It is a truncated hash of the public key, it does not invert, and no call here
accepts or returns one.

### Ports

Ports are FSP ports, carried inside the encrypted FSP envelope. They are
tiered.

| Range | Use | What a program may do |
| ----- | --- | --------------------- |
| 0-255 | Protocol use | Refused. |
| 256-1023 | FIPS standard services | Refused. Port 256 is the IPv6 shim. |
| 1024-49151 | Application, well known | Name it explicitly. |
| 49152-65535 | Application, ephemeral | Name it explicitly, or ask for 0 and be given one from this range. |

Nothing reserves the upper range against explicit use. A service that wants a
fixed port above 49151 may hold one, and ephemeral allocation will not take it
away, because the sweep skips a port already held.

**The refusal applies to the remote port as well as the local one.** A program
cannot send to a peer's port 256 and inject into its IPv6 plane. By the same
rule, a peer listening below 1024 is unreachable from here: the `connect` is
refused with `EADDRNOTAVAIL` before any node state is touched.

**Port 0 means "any port"**, for both calls, and it is the only spelling of
that. This matches `bind(2)` with port 0. `local_addr()` afterwards reports the
port actually held, which is `getsockname`.

A local port has exactly one owner, a listener or one connected flow, never
both. A connected flow owns its local port and frees it when the flow closes.
A flow accepted from a listener shares the listener's port and does not own it,
so closing an accepted flow frees no port; the port returns when the listener
drops. Ephemeral allocation sweeps forward from the last claim and wraps once,
so a port is not immediately reused after release.

## The Rust surface

The crate module is `fips::native::client`. It is gated to Unix targets.

```rust
use fips::native::client::{FipsAddr, FipsListener, FipsStream, ToFipsAddr};
```

`SOCKET` is a `&str` constant holding `/run/fips/api.sock`, the packaged path.
`XOnlyPublicKey` is re-exported from `secp256k1` so a caller needs no direct
dependency on that crate.

### The Berkeley mapping

The descriptor is a real socket. Everything a program does with a flow after
setup is the operating system, not this API.

| Berkeley | Here | Notes |
| -------- | ---- | ----- |
| `socket()` | none | There is no unbound object to make. `connect` and `bind` each return one already bound. |
| `bind()` | `FipsListener::bind` | One setup call. Port 0 asks the daemon to choose. |
| `listen()` | none | Folded into `bind`. The backlog is node configuration, not a caller's argument. |
| `connect()` | `FipsStream::connect` | One setup call. A local registration that contacts no peer. |
| `accept()` | `FipsListener::accept` | Blocks until a flow arrives. One `recvmsg`, no round trip to the daemon. |
| `send()` | `FipsStream::send` | One datagram, whole or not at all. One local size check, then one syscall. |
| `recv()` | `FipsStream::recv` | One datagram. `Ok(0)` is an empty one and only that. |
| `poll()`, `select()`, `epoll` | the same calls | Both types are `AsFd` and `AsRawFd`. |
| `fcntl(O_NONBLOCK)` | `set_nonblocking()` | On both types. Read-modify-write, so a flag the caller set survives. |
| `close()` | drop | Dropping releases the flow or unbinds the port. There is no method. |
| `getsockname()` | `local_addr()` | A field read of what setup reported. It cannot fail. |
| `getpeername()` | `peer_addr()` | The same, for the far end. |
| `SO_RCVTIMEO` | `set_read_timeout()` | On a flow, with `set_write_timeout` and both getters. |
| `SO_RCVBUF`, others | via `AsFd` | `setsockopt` on the descriptor. The surface exposes no option beyond the deadlines. |
| `inet_pton()` | npub decode | bech32, locally, with no lookup. |
| `inet_ntop()` | npub encode | Its exact inverse. |

Four differences from Berkeley remain. There is no `socket()` and no
`listen()`, because a descriptor cannot exist before the daemon has agreed to
make one. A successful `connect` proves nothing about the peer. `Ok(0)` from
`recv` is an empty datagram rather than end of file. And there is a payload
ceiling, reported per flow, which TCP has no equivalent of.

### FipsAddr

One end of a flow. The fields are private, so an address in hand always names
a valid key.

`Copy`, `Debug`, `Clone`, `PartialEq`, `Eq`. **It derives neither `Hash` nor
`Ord`**, so it cannot key a `HashMap` or a `BTreeMap`. Key on
`addr.key().serialize()` or on `addr.to_string()` instead.
`std::net::SocketAddr` derives both, so the omission is a surprise rather than
a convention.

| Call | Returns, and how it fails |
| ---- | ------------------------- |
| `new(key, port)` | The address. Infallible: both arguments are already well typed. Port 0 and the reserved tiers are representable and are refused later, by the daemon, at setup. |
| `key()` | The public key, by value. Infallible. |
| `port()` | The port. Infallible. |
| `Display` | Writes `npub1...:4242`. Pure bech32, no daemon, no lookup. |
| `FromStr` | Reads that back. `EINVAL` for no colon, a port that is not a `u16`, or a head that is not an npub. An nsec is refused despite being bech32 of the right length. |

`Display` and `FromStr` are exact inverses. Parsing splits on the last colon
and is purely local, so it fails identically with no daemon running. The colon
is unambiguous because the bech32 character set does not contain one.

### ToFipsAddr

The mirror of `std::net::ToSocketAddrs`. One generic parameter takes every
spelling of one address. It is taken by `&self`, so a caller never gives up
ownership, and **no implementation opens a socket or contacts the daemon**. The
only error any of them produces is `EINVAL`.

| Implementation | Notes |
| -------------- | ----- |
| `FipsAddr` | Returns a copy. Structurally infallible. |
| `(XOnlyPublicKey, u16)` | The binary address, already parsed. Structurally infallible. |
| `([u8; 32], u16)` | 32 raw bytes. The one binary form that can be rejected: `EINVAL` if the bytes are not a valid x-only public key, which `[0u8; 32]` is not. |
| `(&str, u16)` | An npub and a port. `EINVAL` if the npub does not decode. The port is taken as given and range-checked later. |
| `(String, u16)` | The same, for a string from `argv` or a config file. |
| `str` | The whole address as `"npub1...:4242"`. Delegates to `FromStr`. |
| `String` | The same. |
| `&T where T: ToFipsAddr` | A blanket implementation over references, so `&addr` and `&&str` work at all. |

There is **no associated iterator type**, unlike `ToSocketAddrs`. An address
here resolves to exactly one endpoint.

The concrete implementations are on the unsized `str` rather than on `&str`.
That is what lets the blanket reference implementation cover `&str` and
`&&str` alike. It makes no difference at a call site.

### FipsStream

One datagram flow, and the descriptor it rides on. A flow is an exact match of
both ends and both ports. **The descriptor is the flow**: it lives while a
process holds that descriptor and ends when the last one closes it.

`Send + Sync + 'static`, with no `Arc` and no borrow. There is **no `Clone` and
no `try_clone`**. Because `send` and `recv` both take `&self`, a shared borrow
across two scoped threads is a full-duplex reader and writer. A program wanting
an owned writer handle reaches for `Arc<FipsStream>`.

#### Constructors

| Call | What it does |
| ---- | ------------ |
| `connect(addr)` | A flow to `addr` from an ephemeral local port, at the packaged socket path. |
| `connect_from(local, addr)` | The same from a named local port. `connect_from(0, addr)` is exactly `connect(addr)`. |
| `connect_at(sock, local, addr)` | The full form, naming the daemon's socket. What a development node and a test harness need. |

All three resolve the address first, so a bad address is `EINVAL` with no
socket opened. Then, in this order: whatever `UnixStream::connect` gives for
the socket path (`NotFound` when no daemon runs or the API is disabled,
`PermissionDenied` on socket permissions, `ECONNREFUSED` when the path exists
but nothing is accepting); `EPIPE` if the daemon vanishes mid-write;
`ETIMEDOUT` if no answer arrives inside the five-second setup deadline; then
the daemon's own refusals; then `InvalidData` for a reply this client cannot
parse.

A stream does not outlive its setup connection, because the connection is not
an object at all. It is a local binding inside the constructor, dropped before
the call returns. What comes back holds an owned descriptor and four `Copy`
scalars.

#### Methods

**`send(&self, buf: &[u8]) -> io::Result<()>`** sends one datagram. There is no
byte count, because a `SOCK_SEQPACKET` message is delivered whole or not at
all. `buf.len() > max_payload()` is `EMSGSIZE` before any syscall, so a caller
learns which datagram was too large rather than finding a gap at the far end.
`EPIPE` means the daemon has gone. Takes `&self`, so it can be called
concurrently with `recv` from another thread.

The library sends with `MSG_NOSIGNAL` rather than writing to the descriptor. A
Rust binary ignores `SIGPIPE` at startup anyway, but a C program that has
loaded this crate would otherwise be killed by a write to a departed daemon
rather than told about it. `EINTR` is retried internally.

`Ok(())` means only that the local socket pair accepted the bytes. See
[Where data disappears](#where-data-disappears).

**`recv(&self, buf: &mut [u8]) -> io::Result<usize>`** receives one datagram
and returns its length. It **blocks by default**: the descriptor arrives
blocking and no timeout is set on it. `set_nonblocking(true)` makes it return
`WouldBlock` instead. `set_read_timeout` bounds a single wait without going
non-blocking. A datagram longer than `buf` is truncated and the remainder
discarded, which is `SOCK_SEQPACKET` behaviour and is not reported; size `buf`
at `max_payload()` and it cannot happen. `EINTR` is retried.

**`Ok(0)` is an empty datagram and only that.** An empty datagram and a closed
peer both produce a zero-byte read, and `MSG_EOR` does not tell them apart. On
the zero-byte path only, the library polls the descriptor with an events mask
of zero and reads `POLLHUP` from `revents`, returning `EPIPE` for a genuine
close and `Ok(0)` otherwise. Without that step a peer could tear down a live
flow by sending nothing. The `EPIPE` that `recv` returns means the daemon went
away, never that a peer finished.

**`peer_addr()`** and **`local_addr()`** return `FipsAddr`, not
`io::Result<FipsAddr>`, unlike their `TcpStream` counterparts. These are field
reads of what the setup reply already carried. `local_addr()` carries the
node's own public key, which on an accepted stream comes from the arrival
message rather than from the listener, so a node holding more than one identity
still answers correctly.

**`max_payload()`** returns the largest datagram this flow will carry.
Infallible. **It is a snapshot** taken when the flow opened and does not track
a later MTU change.

**`set_read_timeout(Option<Duration>)`** and **`set_write_timeout`** bound one
`recv` or one `send`, as their `TcpStream` counterparts do. `None` clears.
**A zero duration is `EINVAL`**, because the kernel reads a zero timeout as
"wait for ever" and a caller passing zero means the opposite. An expiring
deadline reports `WouldBlock`, the same answer a non-blocking descriptor gives.
**`read_timeout()`** and **`write_timeout()`** read them back, `None` when
unset. The two directions are separate options, and setting one leaves the
other alone.

**`set_nonblocking(bool)`** puts the flow in or out of non-blocking mode. In
that mode `recv` returns `WouldBlock` rather than waiting, and so does `send`
when the daemon is not draining the flow fast enough. **A flow from `accept` is
blocking however its listener was set**: they are separate sockets and the
daemon hands over a fresh one.

**`AsFd`** and **`AsRawFd`** both return the flow's descriptor. Prefer `AsFd`:
its borrow cannot outlive the stream, so a reactor cannot hold a registration
for a descriptor that has since been closed and its number reissued. **The
stream keeps ownership** either way. Do not close the descriptor and do not
wrap it in anything that takes ownership, because the stream's own drop is what
releases the flow. This is the route to `SO_RCVBUF` and every other socket
option the surface does not expose.

A descriptor that survives an `exec` into a child holds the flow open after
this process closes its own copy, and the flow keeps its slot against the
node's ceiling until the child exits. The library requests close-on-exec when
it takes the descriptor, so this happens only if a program deliberately clears
the flag.

### FipsListener

A held local port, and the descriptor arriving flows are delivered on. **The
listener is a descriptor**, so it joins an existing `poll`, `select` or `epoll`
loop with no new mechanism, and `accept` is one `recvmsg` on it.

`Send + Sync + 'static`, no `Clone`, no `try_clone`, no explicit `Drop`.

**`bind(port)`** holds `port`, or an ephemeral one when `port` is 0, at the
packaged path. **`bind_at(sock, port)`** is the same, naming the daemon's
socket. Failures are the socket-path and setup-deadline rows above, plus
`EADDRINUSE` when a listener or a flow already holds the port, and
`EADDRNOTAVAIL` for a reserved tier or an exhausted ephemeral range.

**`accept() -> io::Result<(FipsStream, FipsAddr)>`** blocks until a flow
arrives. One `recvmsg`, one arrival: a `SOCK_SEQPACKET` message carries exactly
its own descriptor. Takes `&self`, so several threads may accept on one
listener concurrently. It does not map a would-block to `ETIMEDOUT`, so a
caller that put the listener in non-blocking mode sees a raw `WouldBlock`.
Failures: `EPIPE` when the message carried no descriptor, meaning the daemon
closed its half; `InvalidData` for an arrival that is not JSON or is missing a
field; and `io::Error::other` if the control buffer overflowed and a descriptor
was lost.

Whatever the peer sent before `accept` returned is already queued on the
returned stream. **Refusing a flow is dropping the stream**, because there is
no other way to refuse one. An unparseable arrival is therefore reported only
after the descriptor it carried has been taken into ownership, so a parse
failure refuses the flow rather than leaking it.

**`incoming()`** returns an `Incoming<'_>`, which borrows the listener for the
iterator's lifetime, so the listener cannot be moved or dropped mid-iteration.

**`local_addr()`** returns the port actually held with the node's own key, not
an `io::Result`.

**`set_nonblocking(bool)`** puts the listener in or out of non-blocking mode.
In that mode `accept` returns `WouldBlock` when no flow has arrived, and so
does every `incoming` item, which makes that iterator spin unless the caller
waits on the descriptor between items. It does not reach the flows the listener
yields: each arrives blocking.

**`AsFd`** and **`AsRawFd`** return the listener's descriptor. **`poll` on it
reports readable exactly when `accept` would not block.**

**There is no `set_read_timeout` here**, following `TcpListener`, which has
none either. A bounded accept is `set_nonblocking` plus a wait of the caller's
own on the descriptor.

**Dropping** closes the descriptor and unbinds the port. Flows already accepted
from it are untouched; flows still pending on it go with it.

### Incoming

The iterator `incoming()` returns. Its item is `io::Result<FipsStream>`: it
calls `accept` and discards the peer address, which is recoverable as
`stream.peer_addr()`.

**It never returns `None`.** A listener has no last flow, and a failed accept
is yielded as an `Err` item rather than ending the iteration, so a `for` loop
over it never falls through. A reader who writes `let flow = flow?;` inside the
loop exits it on the first transient error, which is a different shape from
`TcpListener` habits.

## Errors

There is no bespoke error type. Every call returns `io::Result`, so the surface
matches `std::net` and a future C binding can return the number directly.

**Match on `err.raw_os_error()` against `libc` constants, never on
`err.kind()`.** `EMFILE` and `EMSGSIZE` both carry
`ErrorKind::Uncategorized`, which is `#[non_exhaustive]` and cannot be named in
a match arm, so `kind()` cannot distinguish the node's flow ceiling or an
oversize datagram from anything else.

### The errno table

Compare against the `libc` constant, never against a literal. The client maps
each name onto `libc::<NAME>` for the platform it was built for, so the number
differs between Linux, FreeBSD and macOS.

| errno | `kind()` | What causes it |
| ----- | -------- | -------------- |
| `EADDRINUSE` | `AddrInUse` | The local port is held, or a flow already exists between those two ends on those two ports. |
| `EADDRNOTAVAIL` | `AddrNotAvailable` | A port in a reserved tier, local or remote, or the ephemeral range exhausted. Reserved rather than `EACCES`, because no program however privileged may hold port 256. |
| `EMFILE` | `Uncategorized` | The node is at `max_flows`, or the socket pair could not be made. Unmatchable by kind. |
| `EINVAL` | `InvalidInput` | An address that does not resolve locally, or a malformed command. |
| `EMSGSIZE` | `Uncategorized` | A `send` above `max_payload()`. Raised locally, before the syscall. Unmatchable by kind. |
| `EPIPE` | `BrokenPipe` | The daemon went away: it exited, the node shut down, or its own read failed. Never a peer finishing. |
| `ETIMEDOUT` | `TimedOut` | The five-second setup deadline, and nothing else on this surface. |
| `ECONNREFUSED` | `ConnectionRefused` | The node is shutting down, a debug command is disabled, nothing is accepting on the socket path, or the reply carried an errno name this client has no row for. |

The last row is the catch-all, so `ECONNREFUSED` is the one code that does not
narrow the cause much. **The daemon sends errno names rather than numbers**,
because a number belongs to the platform the program was built for and the
daemon is not it. An unknown name is read as `ECONNREFUSED` for the same reason
a missing one is. The daemon also sends a human-readable message, and the
client discards it, so no caller can come to depend on prose.

### The errors that carry no errno

Three shapes have no `raw_os_error()` at all.

**`ErrorKind::InvalidData`** and **`io::Error::other`** both mean this daemon is
not speaking the protocol: a reply or an arrival that is not JSON, an unknown
or missing status, a missing or malformed field, a port outside `u16`, a reply
carrying no descriptor, a descriptor arriving on a read that completed no line,
more than 64 KiB with no newline, or a truncated control message. None is worth
retrying, and none is a condition a correct daemon produces.

**`ErrorKind::NotFound`** on a setup call means no daemon is running, or the
native API is disabled, which is the default.

### What is worth retrying

`EMFILE` and `EADDRNOTAVAIL` from an exhausted ephemeral range are load
conditions and may clear. A retry with a backoff is reasonable, and a program
that retries without one contributes to the exhaustion. `ETIMEDOUT` and `EPIPE`
mean the daemon is unhealthy or gone, so the useful retry is the whole setup
sequence and not the one call. `EADDRINUSE`, `EADDRNOTAVAIL` from a reserved
tier, `EINVAL` and `EMSGSIZE` are decisions about the arguments and produce the
same answer every time.

## Where data disappears

The API is datagram-unreliable. Nothing on this surface confirms delivery.
There is no acknowledgement, no retransmission, no ordering guarantee and no
flow control between the two ends. A program that needs confirmation gets it
from the peer, in the payload.

Four places lose data with nothing reported to the client.

**A full per-flow queue.** Inbound datagrams beyond `pending_per_flow` are
dropped with a trace log and no client-visible signal. A program that stops
reading a flow loses datagrams and is never told.

**A listener that does not accept fast enough.** Whole arriving flows are
discarded, counted inside the daemon as `ListenerNotReading`. The bound on how
many flows a stalled listener holds is not the backlog: the send buffer on a
listener's pair is sized generously, because the approximation must err toward
accepting an arrival a program would have read. A program that binds a listener
and stops reading it accumulates flows on the order of `max_flows` rather than
of `backlog`.

**An outbound datagram sent before a session exists.** The first `send` on a
new flow almost always takes this path, because `connect` contacts no peer and
leaves no FSP session behind it. The node holds the datagram and starts a
handshake. What holds it is bounded twice: at
`node.session.pending_packets_per_dest` datagrams for one destination, past
which a further datagram evicts the oldest one held, and at
`node.session.pending_max_destinations` destinations, past which a new
destination's datagram is dropped outright. The defaults are 16 and 256.
Neither eviction reaches the caller.

**An outbound datagram after the MTU has fallen.** `max_payload()` is a
snapshot taken at setup. The daemon re-checks each outbound datagram against
the node's current limit and drops it silently if the transport MTU has since
fallen.

### The drop causes, and what they mean

An inbound datagram can be refused for eight reasons, which render as seven
texts: a pending flow's full queue and an established flow's are distinct to a
counter and alike to a client. The texts are what `DropReason::as_str` produces;
the counter names are what `fipsctl stats metrics` reports under `native`.

| Text | Counter | Condition |
| ---- | ------- | --------- |
| `no listener or flow on that port` | `drop_no_port` | Nothing holds the destination port. |
| `listener backlog full` | `drop_backlog_full` | A listener holds the port but will not hold another pending flow. |
| `node flow ceiling reached` | `drop_too_many_flows` | The node is at `max_flows`. |
| `queue full` | `drop_pending_queue_full`, `drop_flow_queue_full` | A flow's queue is full, whether it is pending or established with a client that is not reading. Two counters, one text. |
| `arrival queue full` | `drop_arrival_queue_full` | The daemon's own queue to a listener's task is full. |
| `listener not reading arrivals` | `drop_listener_not_reading` | A listener's client is not reading its descriptor, so the arrival could not be written to it. |
| `listener closed` | `drop_listener_gone` | A listener's client closed its descriptor between the arrival being taken off the queue and being written. |

**None of these reaches a client for real traffic.** There is no drop event and
no reply reports one. The texts are visible only through the debug `arrive`
command, which reports `dropped: <text>` as its outcome; the counters are
readable at any time through the control socket.

`drop_oversize` is a ninth counter and is not in this table, because it is not a
dispatch refusal: it counts an **outbound** datagram the daemon discarded when
the transport MTU had fallen below it, which is the fourth case above.

### No framing, in either direction

There is no header and no length prefix. One send is one datagram and one
receive is one datagram. A program that adds its own length prefix on top of a
message-boundary-preserving transport is paying for something it already has.

### Seeing what a node holds

Neither type reports the node's state, and the client module exposes no
statistics. `fipsctl show native-flows` is the only way to see what a node
holds, and `fipsctl stats metrics` under `native` carries the per-cause drop
counters that no program is told about. See
[cli-fipsctl.md](cli-fipsctl.md) and
[control-socket.md](control-socket.md).

## What a daemon restart costs

**Every flow and every listener ends when the daemon does**, and descriptors do
not survive it. The daemon's halves close with the process, so a program reading
one gets `EPIPE` and a program writing one gets the same. There is no
reconnection and no resumption: a program that must survive a restart re-runs
its setup calls and gets new descriptors.

**Datagrams already sent and not yet forwarded are lost.** At an orderly flow
close there is nothing in flight, because a flow's reader forwards what the
client wrote and only then notices the flow is over. At daemon exit every reader
stops at once with no such notice. The window is small and nothing bounds it.

A program that needs to know its last datagram reached a peer needs an
acknowledgement from that peer. Neither this API nor the wire beneath it has one
to offer.

## The line protocol

The Rust client hides all of this. It is documented because a client in
another language has to implement it. For the obligations such a client
carries, see
[../how-to/write-a-native-api-client.md](../how-to/write-a-native-api-client.md).

### Framing

The encoding is the control socket's, so a client that speaks one speaks both.
One JSON object per line, terminated by `\n`.

A request is:

```json
{"command": "connect", "params": {"peer": "npub1...", "remote_port": 4242}}
```

Every command requires `params`. A request without the key is refused with
`command '<name>' requires params`.

A command line is capped at 8192 bytes. A longer one ends the connection with
`native API command too large`. **That is the only condition that ends the
connection instead of producing a reply.** The cap is applied whether or not
the chunk in hand holds the newline, so a well formed 9000-byte line ends the
connection exactly as a runaway one with no newline does. The connection is
dropped with nothing written back, so a client sees end of file and never a
message.

Two kinds of line come back, and only two. A success:

```json
{"status": "ok", "data": {}}
```

And a refusal, which carries the code a client acts on and prose it must not
match against:

```json
{"status": "error", "data": {"errno": "EADDRNOTAVAIL"},
 "message": "port 256 is reserved for FIPS standard services"}
```

**There is no third kind.** No event is pushed on this connection and nothing
arrives on it unsolicited, so a reader that sends a command and takes the next
complete line as its answer is correct. A refusal is a normal reply line and
never drops the connection. A reply carrying no `errno` at all is read as
`ECONNREFUSED`, which covers a daemon older than the field.

### The arrival message

**An arriving flow is not a line.** It is one `SOCK_SEQPACKET` message on the
listener's own descriptor, with **no trailing newline**: the message boundary
is the framing, and a newline would offer a client a second framing to rely on.

Its seven fields are `flow_id`, `peer` and `node` as npubs, `local_port`,
`remote_port`, `max_payload` and `held`. The `node` field is carried so an
accepted flow can answer `local_addr` without consulting the listener that
produced it. `flow_id` is the same identifier a `connect` reply carries and the
name the debug commands take.

**`held` is the one field a client cannot infer.** It counts the datagrams the
daemon has already written onto the flow's descriptor before this message,
because the hand-off writes every held datagram first and the arrival last. It
says exactly how many `recv` calls a client may make on a newly accepted flow
without blocking. The Rust client reads neither `held` nor `flow_id`, because
neither names anything a caller can name. A client in another language may
ignore both on the same reasoning; it cannot ignore that they are there.

### Passing the descriptor

The daemon builds an `AF_UNIX` `SOCK_SEQPACKET` socket pair with
`SOCK_CLOEXEC`, keeps one half, and sends the other over `SCM_RIGHTS` in the
ancillary data of the same `sendmsg` that carries the reply line. It makes its
own half non-blocking and leaves the client's half blocking. `SOCK_SEQPACKET`
is what preserves message boundaries in both directions, which is why the
payload needs no framing.

A refused `connect` leaves the port free: the socket pair is built before the
port is claimed, so a failure to build it needs no rollback.

### The setup call

One `AF_UNIX` `SOCK_STREAM` connection to the socket path, one command line
written, one reply line read. Replies come back in command order, and several
commands are permitted on one connection, so a client may pipeline. The shipped
Rust client does not: it opens a connection per setup call and drops it before
returning.

**The connection owns nothing.** Closing it releases no flow and no listener,
and a descriptor kept across the close keeps working. What owns the flow is the
descriptor.

## Command reference

Five commands. Two are the interface; three are debug scaffolding, off by
default.

| Command | Carries FD | What it does |
| ------- | ---------- | ------------ |
| `connect` | yes | Open a flow to a peer named by npub. Returns the flow's descriptor. |
| `listen` | yes | Hold a local port. Returns the listener's descriptor. |
| `stats` | no | Debug. Report what the daemon received on a flow. |
| `inject` | no | Debug. Write bytes into a flow from the daemon's side. |
| `arrive` | no | Debug. Dispatch a datagram as though a peer had sent it. |

**There is no close command, no accept command, no reject command, and no
command to enumerate flows.** Closing a descriptor does the first three, and
`fipsctl show native-flows` does the fourth from the control socket.

### connect

| Parameter | Type | Meaning |
| --------- | ---- | ------- |
| `peer` | string | The far end, as an npub. |
| `remote_port` | u16 | The far end's port. Required. |
| `local_port` | u16 | Optional. Absent, `null` and `0` all mean an ephemeral port. |

Reply data: `flow_id`, `local_port`, `remote_port`, `peer` (the daemon's own
re-encode of the key, not an echo of what the caller wrote), `node` (this
node's own npub), and `max_payload`. Carries the flow's descriptor.

Refusals, in the order they are decided, which is what lets a client read an
`EADDRNOTAVAIL` as a tier refusal rather than an exhaustion:

1. `EADDRNOTAVAIL`: the port is in a reserved tier, either port. Decided before
   any node state is touched.
2. `EINVAL`: the npub does not decode.
3. `EMFILE`: the socket pair could not be built, or the node holds its maximum
   flows.
4. `EADDRINUSE`: the named local port is held, or a flow to that peer between
   those two ports already exists.
5. `EADDRNOTAVAIL`: no ephemeral port is free.
6. `ECONNREFUSED`: the node is shutting down.

### listen

One parameter, `local_port` (u16), where absent, `null` and `0` all mean an
ephemeral port. Reply data: `local_port`, `node`, `backlog`. **Carries the
listener's descriptor**, and a reply that carried none is a daemon that is not
this one.

`backlog` reports the depth the daemon will hold for this listener, so an
operator can size a client's reader against it. Nothing on the Rust surface
takes a depth as a parameter or exposes the reported one.

Refusals: `EADDRNOTAVAIL` for a reserved tier or an exhausted ephemeral range;
`EADDRINUSE` when the port is held, whether by another listener or by a
connected flow; `EMFILE` when the socket pair could not be built;
`ECONNREFUSED` when the node is shutting down.

A flow announced on a listener but never taken is discarded after five seconds.
This is not an accept timeout and a client cannot reach it: the window it
bounds is a hand-off between two tasks inside the daemon, not a client's round
trip.

### The debug commands

`stats`, `inject` and `arrive` exist so the daemon's own checks can drive the
receive and dispatch paths without a peer. They are answered only where
`node.native_api.debug_commands` is set, which is off by default and which no
packaged node sets. A node with the key unset refuses all three by name, with
`ECONNREFUSED` and a message naming the key that would admit them, so a client
can tell "this node will not" from "this build cannot".

**Do not build a client on them.**

`stats` takes `flow_id` and reports `flow_id`, `local_port`, `rx_datagrams`,
`rx_bytes` and `closed`. The counters are the daemon's view of what the client
wrote into the descriptor, independent of whether any of it then reached a
peer.

`inject` takes `flow_id`, `data` (a hex string) and an optional `repeat`
(default 1, maximum 64). It writes `repeat` separate datagrams of those bytes
onto the flow's descriptor from the daemon's side. The flow table it names into
is the node's, not the connection's, so a caller that can reach this command
can write into any flow on the node.

`arrive` takes `peer` (npub), `src_port`, `dst_port` and `data` (hex), and
drives the same delivery decision the real receive path uses. It replies `ok`
whenever the node answers at all:

```json
{"status": "ok", "data": {"outcome": "announced", "flow_id": 9}}
```

`outcome` is `delivered`, `announced`, `held`, or `dropped: <cause>`.
`flow_id` is non-null only for `announced` and `held`. The peer's key is decoded
from the npub the caller named, which makes it client-asserted rather than
authenticated. Port tiers are not checked here.

## Compiled-in bounds

Three bounds are not configurable: a command line of 8192 bytes, a per-arrival
send-buffer allowance of 4096 bytes on a listener's pair, and a `repeat` of 64
on the debug `inject`. The daemon reads each descriptor with a 65535-byte
buffer, which is above anything the wire carries.

`pending_per_flow` has a compiled ceiling of 64, checked when the configuration
loads rather than at the first arrival: the whole held batch is written onto a
socket pair whose client half has not been sent yet, so a larger value could
leave a listener's task with a write it cannot complete. Both it and `backlog`
have a floor of 1. A `backlog` of zero admits no flow at all. A
`pending_per_flow` of zero is worse, because the arrival is announced and the
datagram that caused it is then refused, so a peer's opening message vanishes
with no refusal a client or an operator can see.

## See also

- [../how-to/use-the-native-datagram-api.md](../how-to/use-the-native-datagram-api.md)
  — enable the API and write a first program
- [../how-to/write-a-native-api-client.md](../how-to/write-a-native-api-client.md)
  — the obligations a client in another language carries
- [../how-to/serve-many-peers-on-one-thread.md](../how-to/serve-many-peers-on-one-thread.md)
  — one `poll` loop instead of a thread per peer
- [../design/fips-native-api.md](../design/fips-native-api.md)
  — what this interface is for, what it is instead of, and what it is not
- [configuration.md](configuration.md#native-datagram-api-nodenative_api)
  — every `node.native_api.*` key and its default
- [security.md](security.md#native-datagram-api)
  — what `fips` group membership grants once the API is on
- [control-socket.md](control-socket.md)
  — the `show_native_flows` response shape
- [cli-fipsctl.md](cli-fipsctl.md)
  — `fipsctl show native-flows`
