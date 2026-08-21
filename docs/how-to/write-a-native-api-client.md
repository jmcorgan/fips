# Write a Native API Client in Another Language

**Goal:** speak the native datagram API's line protocol directly, from C,
Python, Go or anything else, without the Rust client module.

Everything here is something the shipped Rust library already does. It is
written out so an author working where there is no such library knows what they
are reproducing. **Each of these was a real defect before it was a rule, and
each fails intermittently rather than outright.**

If you are writing Rust, you do not need this guide. Use
`fips::native::client` and see
[use-the-native-datagram-api.md](use-the-native-datagram-api.md).

For the protocol itself — the framing, the reply shapes, the commands and their
refusals — see
[../reference/native-api.md](../reference/native-api.md#the-line-protocol).

## Step 1: Read the setup connection with recvmsg, never with a buffered reader

**Every read on the setup connection is a `recvmsg` with an ancillary buffer.**
A plain `read` consumes a descriptor-bearing message's bytes with no control
buffer, and the kernel then closes the descriptor rather than queueing it. The
reply looks perfectly correct and the flow is silently gone.

This applies to both setup commands: a `listen` reply carries a descriptor as
much as a `connect` reply does. In any language it means no buffered reader, no
`BufReader`, no `readline`, and no library that wraps the socket in a stream
abstraction. Keep the line buffering in your own code, over `recvmsg`.

Read a listener's own descriptor the same way, for the ancillary data and the
close-on-exec flag. One message there is one arrival carrying exactly its own
descriptor, so there is nothing to associate.

## Step 2: Attach a descriptor to the last complete line of its read

**A descriptor belongs to the last complete line of the read that carried it,
never to the next line the reader assembles.** A `recvmsg` returning ancillary
data ends exactly at the end of the `sendmsg` that carried it, but it may begin
with any amount of data written before it.

A client that sends one command per connection reads one line and cannot hit
this. A client that pipelines two setup commands on one connection can: the
first reply and the second, descriptor-bearing reply arrive as one read, and a
reader that attached the descriptor to the first would hand the flow to the
wrong caller.

Two corollaries:

- A read that carries a descriptor and completes no line must be **reported**
  rather than held. Holding it means guessing which later line it belongs to.
- A descriptor that arrives with a line you are going to discard must still be
  **closed**, or the flow leaks.

Neither can happen while the daemon writes exactly one whole line per `sendmsg`
and treats a short write as an error, which it does. That is an invariant of
two programs, though, not of the socket type.

## Step 3: Treat a zero-byte read as end of file only when POLLHUP is set

**An empty datagram and a closed peer both produce a zero-byte read, and
`MSG_EOR` does not tell them apart.** On Linux 6.8, `recvmsg` on an `AF_UNIX`
`SOCK_SEQPACKET` socket returns `msg_flags == 0` for a normal message, an empty
message and end of file alike, so the flag carries no information.

`POLLHUP` does discriminate. After a zero-byte read, a queued empty datagram
leaves the socket with no events pending, while a closed peer leaves `POLLHUP`
set and latched. Poll with an events mask of **zero**, because `POLLHUP` is
reported in `revents` whether or not it was requested. The poll costs nothing:
it runs only on the zero-byte path and does not block.

Both directions of the mistake are real. Reading an empty datagram as a close
lets a peer tear down a live flow by sending nothing, and presents as a
spurious disconnect. Reading a close as an empty datagram leaves the caller
spinning on a dead flow.

Note what a close here means: the daemon went away, never a peer finishing.

## Step 4: Send with MSG_NOSIGNAL

A datagram written to a flow whose daemon half has gone, or a command written
to a daemon that has exited, raises `SIGPIPE`, whose default disposition kills
the process.

Rust ignores the signal at startup, and CPython sets it to `SIG_IGN`, so a
program in either language sees `EPIPE`. **A C or C++ client that has not
changed the disposition simply dies.** The daemon and the shipped client pass
the flag on every send.

## Step 5: Set a deadline on the setup socket

Set `SO_RCVTIMEO` on the setup connection and rewrite the resulting would-block
into `ETIMEDOUT`. The shipped client uses five seconds.

Without it, a daemon that accepted your connection and then stopped answering
blocks the setup call forever. This is also what keeps `ETIMEDOUT` to exactly
one producer on the surface, which is what lets a caller read it.

## Step 6: Keep descriptor hygiene

Five rules. Each one leaks a flow or loses one when broken.

**Request close-on-exec** with `MSG_CMSG_CLOEXEC` on the `recvmsg`, rather than
setting it afterwards. Without it the descriptor survives an `exec` into a
child, the child's reference holds the flow open after this process closes its
own, and the flow keeps its slot against the node's ceiling until the child
exits.

**Walk the whole control buffer**, not only the first header. Close extra
descriptors rather than dropping them on the floor.

**Check for truncation after taking the descriptors, not before.** A
`MSG_CTRUNC` test that returns early leaks whatever did arrive.

**Lift the descriptor out of an arrival you cannot parse** before discarding
the message. Refusing a flow is closing its descriptor; discarding the message
without taking it leaks the flow instead.

**Bound the partial line.** A daemon that stopped sending newlines would
otherwise grow your buffer without end. The shipped client caps it at 64 KiB,
well above any reply.

## Step 7: Read the errno name, never the message

The refusal's `data.errno` is the contract. The `message` is for an operator
reading a log.

A client that matched on English would break on a wording change. The shipped
client discards the message entirely so that no caller can come to depend on
it, and the daemon's own match over its error types is exhaustive precisely so
a new refusal cannot reach a client without a code.

A reply carrying no `errno` at all should be read as `ECONNREFUSED`, which
covers a daemon older than the field. The errno table is in
[../reference/native-api.md](../reference/native-api.md#the-errno-table).

## Step 8: Size the receive buffer, and add no framing

Size every receive buffer at the flow's `max_payload`, read from the reply and
never computed.

`SOCK_SEQPACKET` truncates a longer datagram, discards the remainder and
reports success. It is detectable: `recvmsg` sets `MSG_TRUNC` in `msg_flags`
when it dropped part of a message. A plain `recv` discards `msg_flags` and so
sees none of it, which is where the belief that truncation is silent comes
from. Test `MSG_TRUNC` as well, and a stale or misread `max_payload` is caught
rather than quietly corrupting a payload.

Do not add framing. There is no header and no length prefix in either
direction. One send is one datagram.

## Step 9: Decide when a flow is over, because nothing else will

Everything above is the library's job. **The termination condition is not**, in
any language.

The v1 wire carries no half-close. Nothing peer-driven closes the daemon's half
of a live flow, so a loop that reads until the flow ends does not terminate.
Your program decides when a flow is over, or nothing does.

The two shapes that work are a bounded exchange, where the program serves a
known number of datagrams per flow and then drops it, and an idle deadline,
where the program sets a read timeout and treats its expiry as the end. A
server that reads "until the flow closes" holds a thread per peer forever and
holds every flow against the node's `max_flows` ceiling.

## Verify it

The repository's test harness drives the line protocol from Python and is the
closest thing to a second implementation:

- `testing/native-api/client.py` — a thin RPC client that runs a script of
  steps over one connection and checks the replies. It implements every rule
  above.
- `testing/native-api/control.py` — reads `show_native_flows` back over the
  control socket while a flow is open.

Check what the node actually holds with `fipsctl show native-flows`, and read
the per-cause drop counters with `fipsctl stats metrics` under `native`.

## See also

- [use-the-native-datagram-api.md](use-the-native-datagram-api.md) — the Rust
  path, where none of this is your problem
- [../reference/native-api.md](../reference/native-api.md) — the surface, the
  line protocol, the command reference and the errno table
- [../reference/control-socket.md](../reference/control-socket.md) — the same
  line framing, for the control socket
