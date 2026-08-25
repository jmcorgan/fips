# FIPS v0.4.2

**Released**: 2026-08-25

v0.4.2 is a maintenance release on the v0.4.x line, and the largest one
this line has carried: 144 commits since v0.4.1. Most of it is security
work. It closes several paths by which a party that could merely reach a
node could take its sessions down, have its traffic attributed to
another node, or steer that node's path MTU; it bounds a set of tables
an unauthenticated party could grow without limit; it closes the
fail-open cases where a local error widened what a node accepted; it
fixes NAT traversal in two places where it was simply not working; and
it protects private key material on disk and clears it in memory. There
is no wire format change.

The new configuration surface is small and optional: three admission and
rate-limiting keys, each with a default that needs no action. The
repository also gains a `SECURITY.md`, so someone with a finding no
longer has to guess at an address or open a public issue.

v0.4.2 is wire-compatible with v0.4.1. No frame gains, loses, or resizes
a field, so a mixed mesh works and nodes can be upgraded one at a time
with no coordinated restart. Three changes narrow what a node accepts,
or change how it acts on a field it already read: the session datagram
hop limit, the path MTU floor, and routing-signal admission. Those three
are what the interop gate is pointed at deliberately, rather than at
connectivity alone. Compatibility is the release's intent and what that
gate checks; it is not a claim that every mixed pairing was exercised.

**Read the upgrade notes before you start.** Two configuration shapes
that loaded in v0.4.1 now refuse to start.

## At a glance

### Before you upgrade

- Two configuration shapes now fail to load: a `node.rekey` interval
  that fires the trigger continuously, and a traversal signal TTL too
  large for the replay window. Both are start-time failures, so a node
  carrying either will not come back after a package upgrade.
- macOS installs now read the ACL, hosts, config and identity files from
  `/usr/local/etc/fips/`, which is where the packaging puts them.

### Security

- Six paths by which an unauthenticated or misattributed packet changed
  a node's session state are closed. One of them terminated the daemon.
- A remote party can no longer drive a destination's path MTU to zero,
  or aim a node's UDP punch packets at addresses of its choosing.
- Nineteen fixes harden a node against a party that can reach it but is
  not an admitted peer: unbounded tables, unauthenticated writes and
  fail-open paths. None changes the wire format and none needs action.
- Private keys are no longer written through a symlink, an existing
  `fips.key` has its mode retightened on every write, and a failed key
  write no longer leaves a node silently running an ephemeral identity.

### Connectivity and performance

- NAT traversal works in two deployments where it did not: a public node
  in open mode, and any host that suspends.
- Roughly 35 ms per tick comes back at 240 peers, and multi-second
  rx-loop stalls during peer retry are gone.

### New configuration, all optional

- `node.rate_limit.session_setup_burst` / `_rate`,
  `node.rate_limit.established_handshake_burst` / `_rate`,
  `node.discovery.nostr.max_concurrent_offers_per_npub`, and
  `node.limits.max_sessions` (default 1024). Each default needs no
  action.

### Dependencies

- `cargo audit` reports no vulnerability, against twelve before, and
  every GitHub Action is pinned to a commit SHA.

## A note on the security content

Most of this release is security work, and most of that work began with
reviews the project did not commission. Over the past month a number of
unsolicited security reviews have arrived, and they share a character:
they are driven by current frontier language models, their authors say
so, and they arrive as specific, carefully written reports citing the
code they describe rather than as vague claims.

The findings have been legitimate. Not every one survived a second
reading, and several described documented behaviour as a defect. But
enough held up under adversarial re-reading that treating this class of
report as noise would have been a mistake, and a substantial part of
what this release fixes was found that way, including issues in code
that had been reviewed before.

None of it has been reported active in a deployment. What these reviews
have produced are reachable defects rather than observed incidents, and
finding them at that stage is the outcome everyone would choose.

This looks like a broader shift rather than something particular to this
project. The cost of a competent first pass over an unfamiliar codebase
has fallen sharply, and open source is benefiting from it: small
projects are now getting the kind of attention that was previously
reserved for large ones. We welcome it, and we would rather receive a
report of this kind than not. `SECURITY.md` describes how to send one.
The most useful reports are the ones that say plainly which parts were
machine-generated and which were verified by a person, because that is
the difference between a lead and a finding, and we assess the two
differently.

## Behavior changes worth flagging

### The session datagram hop limit now follows IP semantics

Delivery to the addressed node is no longer gated on the hop limit, and
a forwarder decrements before deciding rather than after. Two cases
change on a deployed line:

| Case | v0.4.1 | v0.4.2 |
| ---- | ------ | ------ |
| Addressed to this node, hop limit 0 | dropped | delivered |
| Transit datagram, hop limit 1 | forwarded at 0 | dropped here |

The reachable radius is unchanged, because the two behaviors compensate
exactly: a path of `h` links still delivers for any source hop limit of
`h` or more. During a rolling upgrade no version mix delivers less far,
and an unupgraded forwarder feeding an upgraded destination delivers one
hop further than either version does on its own.

What an operator will see move is the counter. `TtlExhausted` now
charges at the node that makes the decision rather than at the hop after
it, so its distribution across a mixed mesh shifts by one hop while the
upgrade is in progress. That is expected and is not a loss of traffic.

### `node.rekey.enabled` governs periodic rekey only

This is a correction to what the setting has always meant rather than a
new field. `enabled` controls whether this node *initiates* periodic
rekey. A rekey a peer drives is still answered when it is off, and two
things that used to sit behind the same gate no longer do: the session
drain sweep and the cut-over that retires an old key epoch now run
either way. A node with rekey disabled previously held superseded keys
for the life of the session.

### New admission defaults you may feel

None of these needs configuration, and none changes an existing key's
value. They are new bounds where there was none.

- `node.discovery.nostr.max_concurrent_offers_per_npub` defaults to 4.
  It sits inside `max_concurrent_incoming_offers` (16), which remains
  the outer bound, so a value above that is inert.
- `node.rate_limit.session_setup_burst` (64) and `session_setup_rate`
  (16.0) meter inbound FSP session setup per authenticated link peer. A
  legitimate peer arriving over the same link as a flooding one shares
  that link's bucket, so establishment behind a flooded neighbour is
  refused until it refills.
- `node.rate_limit.established_handshake_burst` and `_rate` are optional
  and normally omitted; the bucket is then derived from
  `node.limits.max_peers`, `node.rekey.after_secs` and
  `node.rate_limit.handshake_max_resends`, so raising the peer limit
  sizes it automatically.
- An accepted inbound TCP or onion connection now has a deadline for its
  first frame. This is a module constant, not a configuration key.
- A remote-supplied path MTU below an actionable minimum is ignored
  rather than applied or stored. Locally derived MTUs are exempt at both
  the seed and the TCP MSS clamp, so a genuinely narrow link, which the
  mesh does use, still adapts.

### Control socket snapshots carry new fields

`show_routing` and `show_status` gained counters this cycle:
`warm_malformed_packets` and `warm_malformed_bytes`, and the four
error-signal counters `unbound_coords`, `unbound_broken`, `unbound_mtu`
and `unbound_forged`. An older `fipsctl` or `fipstop` reading a newer
daemon gains unknown fields rather than losing known ones. If you scrape
those snapshots, expect additions, not removals. Two other new counters,
the framing `payload_len_mismatch` and the setup-message refusal
counters, are not yet readable over the control socket.

### The bloom announce sweep changes where its cost sits

Peer bloom filters are now computed for every recipient in one union
sweep instead of being rebuilt per recipient. The result is exactly
equal, not approximately: merging is a bytewise OR. The trade-off,
measured rather than assumed, is that the sweep does its full work
regardless of how many peers are ready, so a tick announcing to one or
two peers costs about twice what it did. Break-even is around three
ready peers, so a small mesh pays slightly more and a large one pays a
great deal less. Cadence, the debounce, the sequence rule and the
fill-ratio cap are unchanged.

## Notable bug fixes

Every item here is a fix for a defect that shipped in v0.4.1. Fixes for
defects introduced and resolved inside this cycle are in the CHANGELOG
and are not repeated here. The CHANGELOG is the complete record; this
section is a selection.

### Session and handshake authentication

This is the release's centre of gravity. Six paths are closed, each of
which let a packet that authenticated nothing change a node's session
state.

- **A truncated inner payload terminated the daemon.** A
  `SessionDatagram` whose inner FSP payload was 4 to 11 bytes, with
  phase 0x0 and the Coords Present flag set, indexed past the end of a
  slice on the coordinate-cache warm path. The receive loop is the
  process's main future, so the panic took the daemon down rather than a
  task, and under the packaged systemd unit the node restarted into the
  same frame. Any peer past a link handshake could send it, and
  admission is default-open.
- **An unauthenticated setup message could hold a session down.** With
  `node.rekey.enabled` false, a setup message naming an established peer
  replaced that peer's session outright, discarding the live keys. The
  message carries no authenticator and its source address is an envelope
  field the sender picks. The established case now arms a handshake
  beside the running session and adopts new keys only after a msg3 whose
  authenticated static key matches the one the session was opened with.
- **A forged `SessionAck` cancelled an in-flight initiation**, and an
  unauthenticated msg3 discarded a completed key epoch. Both took 57
  bytes of the right length from anyone who could reach the node, and
  both were repeatable. The setup path is now also rate limited, keyed
  on the authenticated link peer the datagram arrived over rather than
  on the address the sender claims.
- **A peer could complete a genuine handshake under another node's
  address.** The responder recorded a session under the source address
  in the datagram without checking it against the static key it had just
  authenticated, so the identity cache, the session map and the
  reconstructed mesh IPv6 all attributed that traffic to the node it
  named. The address is now derived from the authenticated key, on both
  the initial and the rekey path.
- **Routing signals were acted on for any address.** `CoordsRequired`,
  `PathBroken` and `MtuExceeded` carry no end-to-end authentication, and
  a node applied their effects for any destination they named. They are
  now refused unless this node has itself bound that destination, and
  each refusal is counted. Signals from a genuine on-path forwarder at
  any distance are unaffected.
- **The established-address waiver admitted the wrong party.** A
  transport with `accept_connections` false still admits an inbound msg1
  sourced from an established peer's address, so a peer re-handshaking
  after a restart is not locked out. Nothing checked that the sender was
  that peer, so any off-path party sourcing from the address obtained a
  full link handshake from a node configured to accept none. The
  handshake is now dropped once the key exchange reveals a static key
  that does not belong to the identity owning that address.

A frame whose declared payload length disagrees with the length that
arrived is also now dropped at the single dispatch point, before that
field can be used as a parsing input. This closes no known defect: on
the stream transports the comparison holds by construction, and on the
datagram transports a short frame already failed the AEAD tag. What
changes is which reason it is dropped for.

### NAT traversal and Nostr discovery

- **Traversal was non-functional on a public node in open mode.** A
  signal is addressed to the merge of the peer's inbox relays, the
  relays its advert nominates, and our own, but the send was rejected
  outright if any single URL in that merge was outside the client pool
  built at startup. One unconfigured relay killed the whole attempt,
  including the sends to relays both sides shared. Measured in an
  open-mode window: 309 attempts, 290 explicit failures, zero successes,
  every failure on `relay not found`. Configured peers were unaffected,
  since they run a matching relay set. Comparison is now on the
  normalized relay URL, so a trailing slash or a different host case
  does not discard a relay that is in fact configured.
- **Traversal broke permanently after the host suspended.** The
  traversal clock cached a Unix timestamp at startup and advanced it
  with a monotonic instant, which does not tick while a machine is
  asleep, so the daemon's idea of the time trailed real time by the
  suspend duration for the rest of the process lifetime. Every
  expiration it published was already in the past, relays dropped the
  offers, and traversal stayed dead until restart. The clock now reads
  the wall clock on every call. A laptop is where this is easiest to
  hit, but any host that suspends or hibernates was affected. Reported
  in [#128](https://github.com/jmcorgan/fips/issues/128).
- **A node could be aimed at third parties.** A rendezvous-enabled node
  punched every address a signed offer named, with no limit on how many
  one offer could carry, so any npub could have it emit a burst of UDP
  packets carrying its own source address at loopback, link-local,
  multicast, broadcast, unspecified or CGNAT addresses. Never-routable
  ranges are now rejected, IPv4-mapped forms are canonicalized first so
  they cannot slip past, port 0 is dropped, private-range candidates are
  punched only when they share a /24 with one of our own addresses, and
  the planned list is capped at eight. Each planning attempt logs what
  it declined and why.
- **A future-dated traversal signal was accepted as strictly fresh.**
  The freshness check measured age with a saturating subtraction, which
  yields zero for any timestamp ahead of the local clock, and nothing
  else bounded the issue time from above. Forward-dating is now
  tolerated only to the same 60s of clock skew already allowed in the
  other direction, and a declared expiry is no longer trusted past the
  issue time plus the configured TTL.
- **One sender could hold every inbound offer slot.** Admission took a
  permit from a single pool before any identity check, with the sender's
  npub used only as a log field. Admission now takes a per-npub permit
  and a global permit together. This does not make the pool
  inexhaustible: Nostr identities cost nothing to generate, so four
  throwaway npubs still saturate the shipped 16-slot pool at an
  unchanged total offer rate. What it buys is that one identity can no
  longer do it alone, and that the two refusals are distinguishable in
  the log.

### Path MTU

A single `MtuExceeded` carrying a very small value drove a session's
path MTU to zero, after which every packet to that destination was
answered with an ICMPv6 Packet Too Big instead of being sent: a
blackhole lasting until the daemon restarted. The same value reached the
SYN-time TCP MSS clamp, where anything at or below 137 saturates the
segment size to zero. The `path_mtu` field is an unsigned per-hop
annotation carried outside the signed proof, and `MtuExceeded` and
`PathBroken` arrive unencrypted with no sender check, so any forwarder,
or anyone able to reach the node, could lower it.

Remote values below an actionable minimum are now ignored at the three
places a remote value is acted on, each with its own warning and
counter, and the per-destination cache has a way back: an entry is
released on a `PathBroken` report, on session idle expiry, and on
handshake timeout, with the local link MTU reseeded in its place.
Entries written by the discovery lookup carrier age out on a deadline of
their own, because a destination this node never opens a session with
reaches none of those three routes. Without it, one response carrying a
floor value pinned that destination's clamp until the daemon restarted.

### Inbound connection slots and rekey admission

- **An unauthenticated remote could lock out inbound peering by staying
  silent.** The peer cap was tested at accept, with no read in between,
  and the frame reader's reads carried no deadline. Pool keys are
  `ip:port`, so N sockets from one address took N slots, and at the 256
  default that closed the node to new peers for as long as the sockets
  stayed open. The first frame now has a deadline, the onion listener
  gets the same treatment, and the handshake reaper now closes the
  transport connection it used to forget. This does not close the whole
  case: a peer that sends one well-formed frame and then goes silent
  still holds its slot.
- **Rekey traffic was being refused on busy nodes, silently.** Rekey and
  restart msg1 on an established link competed with stranger admission
  for one shared token bucket. Measured on a field node at roughly 245
  peers: 8753 msg1 refused in 25 minutes, with 159 of the 201 distinct
  sources being peers it already held sessions with. Nothing errored and
  no session dropped, so the only symptom was a flat `rekey_armed`.
  Inbound msg1 is now classified before it is limited and draws on its
  own bucket. Nodes upgrade with no config change, and the
  `Msg1 rate limited` line now says which limb refused.

### Identity and key files on disk

- **A private key write followed a symlink**, because the single write
  path opened with create and truncate and no `O_NOFOLLOW`. Both writers
  now share an open helper that carries it.
- **An existing `fips.key` kept a loose mode forever.** The mode was
  supplied only through `open(2)`, which the kernel honours on creation
  and ignores otherwise, so a key file at 0644 stayed 0644 through every
  rewrite. That needs no attacker: one `chmod`, or a restore that did
  not preserve modes, leaves the key readable indefinitely. The mode is
  now applied to the open descriptor before any secret bytes are
  written. On Windows neither protection applies and the file inherits
  the parent directory's ACLs; that exclusion is deliberate.
- **A failed key write left a node running an ephemeral identity in
  silence.** Six write results in the identity path were discarded, and
  the sharpest was in `persistent` mode: a failed write to `fips.key`
  fell through to an ephemeral identity with no message, so a node asked
  for a stable identity changed its npub, its routing address and its
  mesh IPv6 on every start, and nothing said so. All six now report.
- **Key material is now cleared when it goes out of scope.** Nothing in
  the crate erased a key before this. Clearing now covers the session
  and handshake keys, the identity keypair, the temporary copies the
  elliptic-curve operations make, encoded secrets, and the private key
  on its way through configuration, including the config file's text,
  since `node.identity.nsec` is read straight out of it. This clears the
  copies the crate owns, not every copy that ever existed: the secp256k1
  key types are copyable, and the hash, key-derivation and cached cipher
  states of the pinned libraries offer no clearing route. Reading the
  residue needs access to the process's memory, or to a core dump or
  swap image of it. **This carries a source-breaking change for library
  consumers; see the upgrade notes.**

### Gateway DNS answers

The gateway's DNS forwarder accepted whatever datagram arrived on its
upstream socket. The upstream query reused the client's own transaction
ID, the socket was wildcard-bound and never connected, the receive
discarded the sender, neither the response ID nor the question was
compared against what was asked, and the returned address was not
checked against the mesh prefix. Because the extracted address is
installed as a DNAT rule with no interface constraint, a forged answer
redirected traffic rather than only poisoning a lookup.

The query now carries a random transaction ID, the socket is connected
so the kernel drops foreign sources, a response must match on ID,
question and type, and the address goes through the validating parser
before any allocation. One deliberate behaviour change: validation sits
before the rcode check, so an upstream answering FORMERR or REFUSED with
an empty question section now yields SERVFAIL rather than having its
rcode relayed. Checking after the rcode would admit a forged NXDOMAIN.

### macOS install layout

On macOS the daemon and `fipsctl` read `/etc/fips/`, a directory the
macOS packaging does not create, while the packaging installs to
`/usr/local/etc/fips/`. The effect was silent in the worst way: a
populated `peers.deny` reported `effective_mode: "default_open"` with
`enforcement_active: false` through `fipsctl acl show`, host-file
aliases went unloaded, and `fipsctl keygen` wrote an identity where the
daemon never read it, so the node kept an ephemeral one. The default
paths now follow the platform's packaging, the system config search path
includes `/usr/local/etc/fips/fips.yaml`, and a key stranded at the
legacy path is adopted with a warning rather than a fresh identity being
generated. Linux and Windows behavior is unchanged.

**macOS users with existing files in `/etc/fips/` should move them to
`/usr/local/etc/fips/`.**

### Robustness under adverse local conditions

- **A failed log write could panic the thread or task that logged.** The
  subscriber reported its own internal errors through `eprintln!`, which
  panics when stderr has also failed, and the shipped supervisor
  configurations make that one condition rather than two: the macOS
  plist points both standard streams at one file, and the systemd units
  route both to journald, so one full disk fails both sinks together. In
  the daemon the casualty was a crypto worker, which takes its share of
  the peer space with it permanently. In `fips-gateway` it was a spawned
  task: the DNS resolver, the control accept loop or the pool tick, none
  of which is observed until shutdown, so the process kept running and
  reporting healthy with mesh name resolution or lease expiry and NAT
  cleanup stopped.
- **Flap dampening could engage only once in a node's lifetime.** The
  arming check tested whether a deadline had ever been set rather than
  whether one was still in effect, so after the first episode a node in
  a second flap storm went on switching parents under hold-down alone,
  and neither the `flap_dampened` counter nor the warning fired again.
  Hold-down was unaffected throughout, which is why the practical cost
  at shipped settings was lost visibility rather than unrestrained
  flapping. Separately, a `node.tree.flap_dampening_secs` large enough
  to overflow the monotonic clock is now capped at one year instead of
  panicking the node when dampening engages.

### Supply chain

- The dependency lockfile moves past a set of advisories against the
  pinned `nostr` 0.44.3 and `nostr-relay-pool` 0.44.1, both of which
  were also yanked. The ones that matter here are the relay-pool
  advisories describing forged events bypassing signature validation and
  unverified relay events being processed: that is the path a node
  learns peer adverts on, and it performs no independent verification of
  its own, so the exposure was a misattributed advert rather than the
  denial of service the summaries lead with. `cargo audit` now reports
  no vulnerability, against twelve before. Four warnings remain that no
  version move fixes.
- Every GitHub Action reference is now pinned to a commit SHA. None of
  the sixty-six was pinned before, including the jobs holding the AUR
  deploy key, the jobs with release write scope, and the packaging jobs
  that run with a signing key in the environment. Sixty-two are full
  SHAs; four are justified in one place, since two actions read the tool
  to install from the ref name itself. The sharper hole was not the
  tags: the OpenWrt workflow fetched a helper binary and a toolchain
  from release URLs with no verification at all, in two jobs holding a
  signing key. Both downloads now check a per-architecture pinned
  SHA-256.

### Limits, provenance checks and fail-closed defaults

Nineteen fixes harden a node against a party that can reach it but has
not been admitted to it. Every claim behind them was assessed and then
re-read by a separate reviewer briefed to refute it, and only what
survived that pass is here. **None changes the wire format**, and none
needs configuration.

They fall into four shapes.

**Tables that an unauthenticated party could grow.** The established
session table had no population cap and now defaults to 1024, tunable
with `node.limits.max_sessions`. The UDP transport's DNS cache grew one
entry per hostname ever dialed and is now bounded at 256 with eviction.
The Ethernet discovery buffer deduplicated beacons with a full scan and
had no cap; it is now a map bounded at 1024 distinct MACs. The lookup
dedup cache was fail-closed at its bound, so a flood stopped every
lookup transiting the node; it now evicts instead of refusing.

**State an unauthenticated packet could change.** A relay-returned Nostr
advert was cached without checking that the peer it named had signed it.
A lookup response was acted on with no correlation against a lookup this
node had issued. A STUN binding response was accepted from any source. A
NAT punch packet was accepted from any address whose digest matched.
Each now checks the thing that binds it.

**Denial paths reachable from off the path.** An epoch-mismatch `msg1`
is authentic but replayable, and accepting it tore down a working
peering; it is now refused while that peering is still carrying
authenticated traffic, and dampened against repetition. The
routing-error limiter was keyed on the field the attacker chooses. The
Nostr notify loop ran two decrypts and a signature verify per event
ahead of any limiter. A retired FSP key epoch could be held resident
indefinitely by a peer that kept using it.

**Local fail-open surfaces.** A read error on `peers.allow` or
`peers.deny` was swallowed and published an empty ACL, which took a
strict allowlist node to admitting everyone; the last good policy is now
held and retried. The control socket and its parent directory were
created under the ambient umask and only tightened afterwards. The DNS
mesh-interface filter was keyed on the configured TUN name and so had
never run on macOS or FreeBSD.

Some findings from the same review pass are not addressed here. Where a
fix requires a wire-format change it is not a candidate for the 0.4.x
line at all, which takes none; that work belongs to a later release.
`SECURITY.md` sets out the trust model this protocol assumes, and it is
worth reading if you are deciding how far to rely on a mesh whose
membership you do not control.

Two portability defects are fixed alongside them: a Windows build
failure and a set of Windows and macOS unit-test failures. Both were
caught by CI on those platforms rather than by review, and the coverage
gap that let them through is recorded at the sites.

### A documented claim that was wrong

The security reference named both Noise patterns unqualified, which told
anyone auditing the stack against the Noise specification that the
construction was standard. It is not, in one respect: the handshake AEAD
passes an empty associated-data field where standard Noise
`EncryptAndHash` uses the handshake hash. Domain separation and
Diffie-Hellman binding survive through the chaining key; transcript
binding is the property actually absent. Nothing in the daemon reads the
handshake hash, so no shipped behaviour rests on it, but anything later
built on it (channel binding, an exporter, cookie binding) would
silently not work. The reference now says so.

## Upgrade notes

There is no wire format change and no coordinated restart. Nodes can be
upgraded one at a time in any order. **One thing must be done before you
upgrade, not after**, because it is a start-time failure rather than a
degradation.

### Check two configuration relations before upgrading

Two configuration shapes that loaded in v0.4.1 are now rejected at
config validation. A node carrying either will not start after the
package upgrade. Both were settings that looked like they disabled
something and in fact made it fire continuously, so a rejection is the
correct behaviour, but it arrives at the least convenient moment if you
meet it for the first time on a restart.

Check your config file before you upgrade:

```bash
grep -nE 'after_messages|after_secs|signal_ttl_secs|replay_window_secs' \
  /etc/fips/fips.yaml
```

On macOS the file is at `/usr/local/etc/fips/fips.yaml`.

**1. `node.rekey.after_messages` must be at least 1.** Zero makes the
message-count arm true on every poll, because the trigger compares with
greater-or-equal, so a node rekeyed on sight rather than never. The
default is 65536. If you set it to 0 intending to disable the arm, use a
very large value instead; there is no upper bound.

**2. `node.rekey.after_secs` must be greater than 15**, the per-session
rekey jitter. Each session offsets the interval by a random value within
plus or minus that bound, so a smaller interval saturates to zero on a
negative draw and rekeys on sight for roughly half of sessions. The
default is 120. Both rekey checks run whether or not `node.rekey.enabled`
is true, so turning rekey on later cannot surface the error at a
surprising moment.

**3. `node.discovery.nostr.signal_ttl_secs` plus 120 must be less than
`node.discovery.nostr.replay_window_secs`.** A traversal signal is
acceptable over its TTL plus 60s of clock-skew grace on each side, and
that span has to stay strictly inside the replay window, or a session id
evicted from the replay cache on expiry is still fresh enough to be
accepted a second time. The relation was documented but unenforced, so
raising the TTL past 180s silently voided it. The shipped defaults, a
TTL of 120 against a window of 300, are unaffected. The error names the
concrete floor for `replay_window_secs`, so if you hit it on a test
start the fix is in the message.

The safest sequence is to run that grep on every node's config first,
correct anything that trips one of the three rules, and only then
upgrade.

### If you use `fips` as a library

**Binaries are unaffected. Skip this section unless you build against
the `fips` crate.**

Four public types gained a `Drop` implementation as part of clearing key
material at end of scope: `Identity`, `ResolvedIdentity`,
`IdentityConfig` and `HandshakeState`. A type that implements `Drop`
cannot have its fields moved out, so this is source-breaking for a
consumer of the library crate even though nothing about the shipped
binaries changes.

`IdentityConfig` is the one most likely to be reached in practice,
because it hangs off the public `Config` as `node.identity`. Code that
moved the nsec out of a configuration value no longer compiles. The fix
is `Option::take` on the field rather than moving the value out.

This is a source break in a patch release, which semantic versioning
does not sanction. It ships anyway because the alternative was holding a
security fix for the next minor, and because the crate is not published
to a registry, so the reachable population is small.

### During and after a rolling upgrade

- `TtlExhausted` charges at a different node than it did, so its
  distribution shifts by one hop while the mesh is mixed. This settles
  once every node reports `0.4.2`.
- If you scrape the control socket, expect `show_routing` and
  `show_status` to carry new counters. An older `fipsctl` or `fipstop`
  gains unknown fields rather than losing known ones.
- On macOS, move `peers.allow`, `peers.deny`, `hosts`, `fips.yaml` and
  `fips.key` from `/etc/fips/` to `/usr/local/etc/fips/`. The daemon
  warns once at startup if it finds any of them only at the old
  location, and it will adopt a key stranded there rather than
  generating a new identity, but the warning is the signal to move them
  rather than to leave them.
- A mesh whose peers advertise a legitimately narrow path MTU should be
  watched once after the upgrade. Locally derived values are exempt from
  the new floor at both the seed and the clamp, so a narrow link is
  expected to adapt as before, but that exemption is asserted in the
  code rather than proven by a test that drives a genuinely narrow path.

Downgrading to v0.4.1 is supported. A config corrected for the three
rules above still loads on v0.4.1, so the correction does not have to be
reverted.

## Getting v0.4.2

- **Linux x86_64 / aarch64**: `.deb` and tarball at the
  [v0.4.2 release page](https://github.com/jmcorgan/fips/releases/tag/v0.4.2).
- **Arch Linux**: `fips` from the AUR.
- **macOS**: `.pkg` at the v0.4.2 release page.
- **Windows**: ZIP at the v0.4.2 release page.
- **OpenWrt**: `.ipk` (OpenWrt 24.x and earlier) or `.apk` (OpenWrt 25+)
  at the v0.4.2 release page.
- **From source**: `cargo build --release` from a checkout of the v0.4.2
  tag (Rust 1.94.1 per `rust-toolchain.toml`; `libclang-dev` is a
  required Linux build prerequisite).
- **Nix / NixOS**: `nix build .#fips` from a checkout of the v0.4.2 tag
  builds the binaries from source with the pinned toolchain and no
  manual prerequisites (see the Nix section of `packaging/README.md`).

The full per-commit changelog lives in
[`CHANGELOG.md`](../../CHANGELOG.md). Issues and discussion at
[github.com/jmcorgan/fips](https://github.com/jmcorgan/fips).

Security reports have a private channel as of this release; see
[`SECURITY.md`](../../SECURITY.md).

## Contributors

Thanks to everyone who contributed code, packaging work, bug reports, or
reviews to this release.

- [@jmcorgan](https://github.com/jmcorgan) (Johnathan Corgan): release
  shepherd; the session and handshake authentication work, path MTU
  bounding, key material protection and clearing, gateway DNS answer
  validation, Action pinning and the dependency refresh, the traversal
  clock fix, spanning-tree and rate-limiting work, and the test harness.
- [@sh1ftred](https://github.com/sh1ftred): the macOS install layout
  fix, so config, ACL and identity paths follow the platform packaging
  ([#132](https://github.com/jmcorgan/fips/pull/132)). First
  contribution to FIPS.

Bug reports and reviews that shaped this release:

- [@Theleifless](https://github.com/Theleifless): reported
  [#128](https://github.com/jmcorgan/fips/issues/128), NAT traversal
  breaking after the host sleeps.
- [@ngmisl](https://github.com/ngmisl): filed
  [#137](https://github.com/jmcorgan/fips/issues/137), the security
  review most of this release's security work answers.
