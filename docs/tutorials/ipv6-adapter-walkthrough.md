# IPv6 Adapter Walkthrough

You have completed [join-the-test-mesh](join-the-test-mesh.md).
Your daemon is peered with `test-us01` and you can ping mesh
nodes by `.fips` name. This tutorial walks the plumbing that
makes that possible: what happens between the moment your shell
types `ssh user@<peer>.fips` and the moment a TCP SYN arrives at
sshd on the far side. Each step is something you can observe
with the running daemon from the previous tutorial.

By the end you will be comfortable reading `fipstop` output and
you will know which design doc to consult when something looks
off.

> **Prerequisites.** The daemon from
> [join-the-test-mesh.md](join-the-test-mesh.md) is running and
> peered with at least one test-mesh node, and your host's local
> resolver is forwarding `.fips` queries to the daemon's DNS
> responder (the system fips-dns.service drop-in does this
> automatically on systemd hosts).

## The path we're tracing

```text
shell  ──ssh──>  libc resolver  ──.fips──>  fips DNS  ──AAAA──>  fd97:...:test-us01
                                                                    │
                                                                    ▼
                                                          kernel IPv6 stack
                                                                    │
                                                                    ▼
                                                                fips0 (TUN)
                                                                    │
                                                                    ▼
                                                             your fips daemon
                                                          (FSP session setup,
                                                           FMP forwarding)
                                                                    │
                                                              UDP / internet
                                                                    ▼
                                                          test-us01's fips daemon
                                                                    │
                                                                    ▼
                                                                fips0 (TUN)
                                                                    │
                                                                    ▼
                                                          kernel IPv6 stack
                                                                    │
                                                                    ▼
                                                                  sshd
```

In a multi-hop mesh the middle would have additional FMP
forwarders between your daemon and the destination. For this
walkthrough you have a single direct link to `test-us01`, which
keeps the trace simple.

## Step 1: Watch the DNS resolution

Ask the system resolver to translate `test-us01`'s npub into its
mesh address:

```sh
dig npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98.fips AAAA +short
```

You should see one AAAA record returning an address such as
`fd97:...`. The prefix is the FIPS ULA range (`fd00::/8`): only
the leading `fd` byte is fixed, and everything after it is hash
output derived from the npub, so the digits beyond `fd` vary per
node.

The query went through `systemd-resolved` (or your platform
equivalent), which routed `.fips` queries to the daemon's local
responder via the drop-in installed by `fips-dns.service`. To
confirm, query the daemon directly:

```sh
dig @::1 -p 5354 npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98.fips AAAA +short
```

Same answer, same fast turnaround — no external DNS traffic in
either case.

The mapping `npub → fd00::/8 address` is deterministic. The
responder hashes the public key into 16 bytes, prepends the
prefix, and returns the result. There is no shared registry; the
address space is self-allocating from the public-key namespace.

If you ask for any non-`.fips` suffix, the responder returns
`REFUSED` — it is intentionally a stub for this single zone, not a
recursive resolver. An unknown `.fips` name returns `NXDOMAIN`.

The full DNS integration is documented in
[../design/fips-ipv6-adapter.md](../design/fips-ipv6-adapter.md).

## Step 2: Watch the session being created

Open `fipstop` against your daemon's control socket:

```sh
sudo fipstop
```

Press `Tab` until you reach the **Sessions** tab. Before any
TCP traffic to `test-us01`, the table is empty (or has rows from
earlier exchanges).

In another terminal, kick off a TCP connection from your host
toward `test-us01`:

```sh
ssh -o ConnectTimeout=5 user@test-us01.fips
```

(`test-us01.fips` resolves to the same address as the npub
form via the installer's `/etc/fips/hosts` entry.)

(It is fine if the SSH attempt fails authentication or if no
sshd is exposed on the far side — what we want to observe is the
session machinery firing, not a successful login.)

In `fipstop`'s Sessions tab you should see a new row appear with:

- `state` cycling from `initiating` to `awaiting_msg3` to
  `established` (the three FSP handshake states).
- `display_name` showing `test-us01` (the `alias` you set in your
  `peers:` block in the previous tutorial).
- A non-zero `last_activity_ms`.

Once `established`, the session row stays put until idle-timeout
expires. The traffic counters and MMP metrics tick as data flows.

> **Watch for.** Some intermediate states may be too fast to
> see at the default `fipstop` refresh rate of 2 s. Run
> `sudo fipstop -r 1` for a faster refresh during the exercise.

## Step 3: Watch the per-session metrics

Switch to the **Performance** tab. Each established session has
a session-layer MMP entry showing:

- `srtt_ms` — smoothed end-to-end round-trip time. Over a
  public-internet path this typically lands in the tens of
  milliseconds; for a US-coast destination from a US client you
  might see 30–80 ms steady-state.
- `loss_rate` — fraction of in-flight payloads inferred lost from
  counter gaps. Stays at 0 on a healthy link; small bursts during
  congestion or path changes.
- `path_mtu` — the end-to-end MTU the session-layer MMP currently
  believes is in force. Starts at the IPv6 floor and climbs as
  PathMtuNotification echoes arrive.
- `etx` and `goodput_bps` — derived metrics, useful as
  steady-state indicators.

The same metrics are available without the TUI:

```sh
sudo fipsctl show sessions | jq '.sessions[] | {display_name, state, mmp}'
```

What these numbers mean is documented in
[../design/fips-mmp.md](../design/fips-mmp.md). Briefly: SRTT is
RFC 6298-style with α = 1/8; loss is bidirectional, inferred from
counter gaps in MMP reports; path MTU is end-to-end-echoed with
hysteresis on increase.

## Step 4: Watch the link below the session

Switch to the **Peers** tab. Each authenticated peer has its own
link-layer MMP block, distinct from the session-layer one above.
The link-layer metrics measure a single hop (here, your daemon
↔ `test-us01` over UDP), independent of any session that
traverses it.

Compare the link-layer SRTT for `test-us01` to the session-layer
SRTT of the session you just created. Because your reach to
`test-us01` is one direct hop, the two should be very close —
the session has no transit forwarders to add latency.

If you reach a node that `test-us01` forwards to (try the
`test-us02` ping from the previous tutorial), the session-layer
SRTT for that destination will be measurably larger than the
link-layer SRTT to `test-us01`. The difference is the time
`test-us01` spent forwarding plus the hop from `test-us01` to
`test-us02`.

In a deeper mesh this divergence grows: link-layer SRTT measures
the direct neighbour, session-layer SRTT measures the full
end-to-end path.

## Step 5: Read the relevant design docs

You have now seen the moving parts. To go from "I can read these
metrics" to "I understand why each one moves the way it does":

- [../design/fips-ipv6-adapter.md](../design/fips-ipv6-adapter.md)
  — DNS responder, identity cache, TUN reader/writer, IPv6 header
  compression, MTU enforcement at the TUN boundary.
- [../design/fips-session-layer.md](../design/fips-session-layer.md)
  — FSP session lifecycle: msg1 / msg2 / msg3, the rekey state
  machine, the drain window for old sessions during cutover.
- [../design/fips-mmp.md](../design/fips-mmp.md) — both link-layer
  and session-layer MMP: report format, SRTT estimation,
  loss/jitter/ETX computation, the trend indicators.
- [../design/fips-mtu.md](../design/fips-mtu.md) — what `path_mtu`
  in `show sessions` means: the proactive forward-path field, the
  reactive `MtuExceeded` mechanism, the hysteresis on increase.
- [../design/fips-architecture.md](../design/fips-architecture.md)
  — the two-layer encryption model: link-layer Noise XX over
  each hop, end-to-end Noise XX over the session.

## What you've learned

- A `.fips` name resolves through a daemon-local stub responder.
  The mapping from npub to `fd00::/8` address is deterministic
  and needs no registry.
- The kernel IPv6 stack treats the TUN adapter as an ordinary
  interface; packets to `fd00::/8` go out via that route. The
  daemon reads them off the TUN, looks up an FSP session for the
  destination (creating one if needed), and forwards them onward
  through its peers.
- The session layer (FSP) and the link layer (FMP) each maintain
  their own MMP metrics. Session-layer metrics measure the path
  end-to-end; link-layer metrics measure a single hop. The two
  align when the destination is your direct peer; they diverge
  when traffic traverses additional hops.
- `fipstop` exposes both views in real time. `fipsctl show sessions`,
  `fipsctl show peers`, and `fipsctl show transports` cover the
  same ground programmatically.

When something looks off in production, the `fipsctl show *`
queries are usually the first stop; the relevant design doc tells
you what the numbers mean and what they should do.
