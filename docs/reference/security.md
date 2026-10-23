# Security Reference

Consolidated security reference covering the nftables baseline, peer
ACL file format, cryptographic primitives, key material in memory,
rekey defaults, replay window, filesystem permissions,
threat-resistance matrix, and default network exposures per
transport. For the threat-model design and
rationale, see [../design/fips-security.md](../design/fips-security.md).
For the operator activation steps and drop-in recipes, see
[../how-to/enable-mesh-firewall.md](../how-to/enable-mesh-firewall.md).

## nftables Baseline

The shipped baseline is `/etc/fips/fips.nft`. It defines a single
nftables table `inet fips` with one chain hooked at `input`, structured
as follows:

| Step | Rule | Effect |
| ---- | ---- | ------ |
| 1 | `iifname != "fips0" return` | Match only traffic arriving on `fips0`; everything else short-circuits. |
| 2 | `ct state established,related accept` | Allow conntrack replies and related ICMPv6 errors. |
| 3 | `icmpv6 type echo-request accept` | Allow IPv6 echo (ping6 reachability). |
| 4 | `include "/etc/fips/fips.d/*.nft"` | Splice in operator drop-ins (empty matches nothing). |
| 5 | `counter drop` | Default-deny everything else; counter increments on every drop. |

Outbound from `fips0` is unrestricted. The baseline is a documented
dpkg conffile — operator edits to `/etc/fips/fips.nft` are preserved
across upgrades.

The systemd unit is `fips-firewall.service` (oneshot). It is **not**
enabled by default; activation is an explicit operator gesture
documented in
[../how-to/enable-mesh-firewall.md](../how-to/enable-mesh-firewall.md).

## Drop-In File Format

Operator extensions live under `/etc/fips/fips.d/` with the `.nft`
suffix. Each file is included inline into the `inbound` chain at the
marked point and may contain any nftables rule lines valid in that
context.

Naming convention: `<purpose>-from-<source>.nft` keeps drop-ins easy
to scan. Examples shipped in the design discussion:

- `ssh-from-bastion.nft` — accept TCP/22 from a single mesh-node address
- `http-from-cluster.nft` — accept TCP/80 from a `/64` mesh-address prefix
- `dns-public.nft` — accept UDP/53 and TCP/53 from any mesh node
- `git-from-trusted.nft` — accept TCP/9418 from a set of mesh-node addresses

After editing, reload via
`sudo systemctl reload-or-restart fips-firewall.service` (or
equivalently `sudo nft -f /etc/fips/fips.nft` since the file is
idempotent).

## Cryptographic Primitives

| Component | Choice | Where Used |
| --------- | ------ | ---------- |
| Curve | secp256k1 | FMP IK, FSP XK, Schnorr signatures |
| Diffie-Hellman | ECDH on secp256k1 (x-only normalized) | Noise IK, Noise XK |
| AEAD | ChaCha20-Poly1305 | FMP link encryption, FSP session encryption |
| Hash | SHA-256 | NodeAddr derivation, Noise key schedule |
| Key derivation | HKDF-SHA256 | Noise key schedule |
| Signatures | secp256k1 Schnorr | TreeAnnounce, LookupResponse proof, Nostr adverts |
| Noise pattern (link) | `Noise_IK_secp256k1_ChaChaPoly_SHA256`, with the deviation below | FMP link layer (IK with epoch payload) |
| Noise pattern (session) | `Noise_XK_secp256k1_ChaChaPoly_SHA256`, with the deviation below | FSP session layer (XK with epoch payload) |

These choices align with the Nostr cryptographic stack
(secp256k1 + ChaCha20-Poly1305 + SHA-256) and the NIP-44 encrypted
messaging standard.

### Deviation: Empty Associated Data in the Handshake AEAD

Both Noise patterns above deviate from the standard construction in one
respect. The handshake AEAD uses an empty associated-data field where
standard Noise `EncryptAndHash` uses the handshake hash `h`.

The choice was deliberate. Using secp256k1 rather than 25519 already put the
construction outside standard Noise, so no standard-Noise peer could be
confused with it, and the transcript hash bought no distinguishing value.

That argument is about domain separation, and on those grounds it holds. It
does not cover transcript binding, which is the property actually absent.
Domain separation and DH binding survive through the chaining key `ck`, which
`mix_key` chains from `ck = h`, seeded from the protocol name in
`SymmetricState::initialize` (`core/src/noise/handshake.rs`). The handshake hash
`h` is maintained at every step and is never fed to the AEAD, so it binds
nothing.

## Key Material in Memory

The daemon clears the copies of secret material that its own code
holds once they are no longer needed: the node's long-term private
key when the identity is dropped, the static and ephemeral keypairs a
Noise handshake holds, the chaining key and handshake hash, the
per-message Diffie-Hellman results, the key-derivation outputs and the
two session keys derived from them, the bech32 and hex encodings of a
secret, and the configuration text that carries `node.identity.nsec`.
The SHA-256 state that hashes
each Diffie-Hellman result and the HMAC states inside HKDF clear
themselves on drop, through the opt-in `zeroize` features of `sha2`
and `hmac`, which the daemon turns on. A completed session keeps its
own copy of the handshake hash and does not clear it, on purpose:
nothing derives a key from it, and the session hands it out to any
caller.

Each erase is a volatile write, and the optimiser does not remove a
volatile write as a dead store. `secp256k1`'s erase follows the write
with a compiler fence, and `zeroize`'s with an optimisation barrier (an
empty `asm!` block on x86_64); those limit how the compiler may reorder
code around the write, but it is the volatile write that keeps the
store. This was checked against generated code rather than assumed: in
an x86_64 release build (Rust 1.94.1, `secp256k1` 0.30.0, `zeroize`
1.9.0), every erase in the Noise handshake and identity code that is
linked into the daemon is present as stores in the machine code.

An erase reaches only the place it is called on. What it does not
reach:

- **Copies left by moves.** Moving a value copies its bytes and leaves
  the old bytes where they were. A handshake state is built on the
  stack and moved several times between being created and being
  dropped. Each of those moves leaves behind, in a stack frame that is
  no longer in use, a copy of the node's long-term private key and,
  once the handshake has started, of its ephemeral key and chaining
  key. Three moves out of the slots on a connection's control machine
  are cleared: when a completed handshake leaves the slot that held it,
  when a session is taken out of its slot for a rekey, and when the
  whole handshake state leaves the machine because the connection is
  promoted to an active peer, resolved as one side of a
  cross-connection, or reaped as stale. In each case the slot is
  overwritten as the value leaves. Other moves are not.
- **Loading the identity from a secret string.** Building the node's
  identity from its key file or from `node.identity.nsec` leaves
  copies of the private key, among them a whole intermediate identity,
  in that constructor's stack frame, and they are not cleared.
- **Registers and spilled temporaries**, which no code in the daemon
  can name.
- **Library state.** The cipher keys cached inside `ring`'s
  `LessSafeKey` have no clearing route. The daemon cannot clear the
  internal temporaries of the `libsecp256k1` C library either; the
  library clears some of its own, such as the nonce and secret scalar
  used in signing, on a best-effort basis.

Clearing therefore shortens how long secret material stays in memory
and removes it from the places the daemon's own code keeps it; it does
not guarantee that a secret is gone from the process. Reading what
remains requires access to the daemon's memory, or to a core dump or
swap image of it.

## Rekey Defaults

Both link-layer and session-layer Noise sessions rekey under one of
two triggers, configurable under `node.rekey.*`:

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `after_secs` | `120` | Time-based rekey threshold. |
| `after_messages` | `65536` | Message-count rekey threshold. |

In addition to the configurable triggers, the daemon retains the old
keys after each cutover so in-flight packets encrypted under them still
decrypt. A link keeps them for a fixed **10-second drain window**. A
session keeps them for 10 seconds after the first message showing the
peer has moved to the new keys, and at most 120 seconds after the
cutover; messages under the old keys do not extend that. Rekey rotates
the Noise key schedule and, on a link, the session indices.

## Replay Window

Both layers use explicit per-packet counters with a sliding bitmap
window for replay protection. The bitmap is **2048 entries** at both
layers — large enough to accommodate UDP reordering and packet loss
without false-positive replay rejection. Counters older than the
window are rejected. The same `ReplayWindow` and
`decrypt_with_replay_check()` implementation is used at both the FMP
and FSP layers.

## Peer ACL

Mesh-level ACL files `peers.allow` and `peers.deny`, in `/etc/fips/`
on Linux and other Unix, `/usr/local/etc/fips/` on macOS and FreeBSD
and `C:\ProgramData\fips\` on Windows, give the operator
allowlist/blocklist control over which npubs may complete the FMP
Noise IK link handshake.

On Windows, v0.5.1 and earlier read both files from `\etc\fips\`,
where any local user can create files. The daemon still reads a
`peers.allow` or `peers.deny` left there, on the current drive (for
the service, normally the system drive), while the same file is
missing from `C:\ProgramData\fips\`, and logs a warning when it
does; when the file is in both places, only the `C:\ProgramData\fips\`
copy is read. `install-service.ps1` creates both files empty in
`C:\ProgramData\fips\`, which ends the fallback, and stops without
installing when it finds either file in `\etc\fips\` on the system
drive with no copy in `C:\ProgramData\fips\`, so that the old list is
reviewed and moved or deleted first. To clear a list, empty its file
rather than deleting it, or an old copy in `\etc\fips\` is read
again.

File format:

- One entry per line. An entry is either a bech32 `npub1...`,
  an alias defined in `/etc/fips/hosts`, or the literal `ALL`
  wildcard (case-insensitive).
- Lines beginning with `#` are comments.
- Blank lines are ignored.

Evaluation order (first match wins, default-allow on no match):

1. `peers.allow` — if the peer matches an entry here (or `ALL` is
   in `peers.allow`), the handshake is admitted, regardless of any
   `peers.deny` entry.
2. `peers.deny` — if the peer matches an entry here (or `ALL` is
   in `peers.deny`), the handshake is refused.
3. Otherwise the peer is admitted.

`peers.allow` is **not** an exclusive gate on its own: an unlisted
peer falls through to step 3 and is admitted unless it appears in
`peers.deny`. To turn `peers.allow` into a strict allowlist, place
`ALL` in `peers.deny` so every unlisted peer is rejected at step 2.

The `ALL` wildcard makes the operator's posture explicit:

- `ALL` in `peers.allow` admits every peer (same effect as the
  default-allow behavior, but documented in the file).
- `ALL` in `peers.deny` blocks every peer except those listed in
  `peers.allow` — the "allowlist-strict" posture.

In practice this collapses to a few common postures:

- **Default-allow with denylist**: leave `peers.allow` empty;
  populate `peers.deny`. All npubs may peer except those listed.
- **Allowlist-strict**: populate `peers.allow` and put `ALL`
  in `peers.deny`. Only the listed npubs may peer; everyone else
  is rejected at step 2.

A populated `peers.allow` with an empty `peers.deny` is not a
strict allowlist — it is equivalent to default-allow plus an
explicit "always-admit" set. The strict variant requires `ALL`
in `peers.deny`.

Aliases are resolved through `/etc/fips/hosts` at file-load
time. If `peers.allow` lists `core-vm` and `/etc/fips/hosts`
maps `core-vm` to a specific npub, that npub is admitted. If
`core-vm` is later remapped to a different npub, the ACL
re-resolves on the next mtime change. Operators should be aware
that ACL semantics follow the `hosts`-file aliasing, not just
the literal npubs visible in the file.

Both files are reloaded automatically when their mtime changes
— no daemon restart or signal is needed. ACL evaluation runs
after msg1 decryption but before any further peer-state
mutation; rate-limited msg1s never reach the ACL.

## Filesystem Permissions

| Path | Owner | Mode | Purpose |
| ---- | ----- | ---- | ------- |
| `/etc/fips/fips.key` | root:root | `0600` | Persistent identity private key (sensitive). |
| `/etc/fips/fips.pub` | root:root | `0644` | Public key (npub). |
| `/etc/fips/fips.yaml` | root:root | `0600` | Daemon configuration (seeded by `postinst` from `/usr/share/fips/fips.yaml.example`; not a conffile). |
| `/etc/fips/fips.nft` | root:root | `0644` | nftables baseline (dpkg conffile). |
| `/etc/fips/fips.d/` | root:root | `0755` | Operator drop-in directory. |
| `/etc/fips/hosts` | root:root | `0644` | Optional hostname → npub map (dpkg conffile). |
| `/etc/fips/peers.allow` | root:root | `0644` | Optional peer allowlist. |
| `/etc/fips/peers.deny` | root:root | `0644` | Optional peer denylist. |
| `/run/fips/control.sock` | root:fips | `0770` | Control socket (members of `fips` group can use `fipsctl`). |
| `/run/fips/api.sock` | root:fips | `0770` | Native datagram API socket, when `node.native_api.enabled` is set (experimental; absent otherwise). |
| `/run/fips/` | root:fips | `0750` | Socket parent directory. |

The `/etc/fips/` paths are the Linux ones. macOS and FreeBSD use
`/usr/local/etc/fips/`; the Windows service keeps the key, config,
hosts and ACL files in `C:\ProgramData\fips\`, which
`install-service.ps1` restricts to SYSTEM and Administrators.

Adding a user to the `fips` group grants `fipsctl` access without
requiring root. The daemon `chown`s the control socket and its parent
directory at bind time, and does the same for the native API socket when
that is enabled.

## Native Datagram API

**Experimental. Disabled by default** (`node.native_api.enabled`, default
`false`), and built on Linux, FreeBSD and macOS only. It is not a stable API
surface, not a reliability layer, and not the v2 external process API. No
compatibility promise is made about it.

**Any user in the `fips` group can impersonate the node on the mesh.** The
API socket is created at mode `0770` owned by group `fips`, and that is the
entire authorization model. A process that can open it can:

- send datagrams under this node's identity to any peer it names, which
  peers authenticate as coming from this node;
- hold any port from 1024 upward and receive mesh traffic addressed to this
  node on it, including traffic another local program expected;
- do both without authenticating, without a capability check, and without
  any record beyond the daemon's own logs.

Group membership is therefore equivalent to possession of the node's
identity for the purpose of sending on the mesh. **On a node with the native
API enabled, treat membership of the `fips` group exactly as you would treat
`/etc/fips/fips.key`.** Grant it to the accounts that are trusted to speak as
the node and to no others, and review it before enabling the API on a shared
machine.

**The file descriptor carries the grant, not the connection.** A setup call
hands the client a socket descriptor and the connection it was made on is then
closed; the flow or the held port lives until that descriptor is closed and
the daemon has let go of the copy it keeps while the descriptor is being
handed over. A descriptor is an ordinary kernel object, so it survives
`fork`, survives `exec` unless the client asked for it close-on-exec when it
received it, and can be handed to another process over `SCM_RIGHTS`. A
process holding one can send as this node on that flow, or receive on that
port, without ever opening the API socket and without being in the `fips`
group.
Nothing revokes a descriptor already handed out. Restarting the daemon closes
its own halves and ends every flow and listener at once, and that is the only
revocation there is.

Two consequences follow for `fipsctl` access. First, the `fips` group is
already the control-socket group, so enabling the native API silently
upgrades every existing `fipsctl` user from "can read node state and manage
peers" to "can send as the node". Second, an operator who wants the two
audiences separated must not enable the API on a node whose `fips` group has
been handed out for monitoring.

`node.native_api.debug_commands` (default `false`) is a second, independent
gate. It admits three commands (`inject`, `stats`, `arrive`) that exist for
the test harness: `arrive` makes the daemon dispatch a datagram as though a
peer had sent it, reaching any listener on this node under any peer identity
the caller names. Leave it off outside a test harness; a packaged node does
not enable it.

**A remote peer holding sessions under several keys can fill the node's flow
ceiling through a server that refuses flows by dropping them.** Until a
program first sends on a flow it accepted, the daemon keeps its own copy of
that flow's descriptor, so a flow accepted and dropped unanswered keeps its
slot against the node-wide `node.native_api.max_flows` until its listener is
dropped. One key's inbound flows, pending and accepted, are held to a quarter
of `max_flows`; an arrival past that share is dropped as
`peer flow limit reached` and counted in `drop_peer_share`. A single peer
opening flows from many source ports therefore stops at its share, but a peer
with sessions under four or more keys can still exhaust the ceiling, and
every other program on the node then gets `EMFILE` on `connect` and silently
loses arrivals on its listeners. The flows that make up a share stay pinned
until the listener is dropped. This is the accepted cost of keeping a flow
alive while its descriptor is on the way to the program; see
[../how-to/use-the-native-datagram-api.md](../how-to/use-the-native-datagram-api.md)
for what releases the daemon's copy.

The socket is local only. It is not reachable over the network, and nothing
about it changes the mesh's own authentication: a peer still verifies the
node's signature, which is precisely why a local caller that can send through
this socket is indistinguishable from the node itself.

See [configuration.md](configuration.md#native-datagram-api-nodenative_api)
for the key list and
[../how-to/use-the-native-datagram-api.md](../how-to/use-the-native-datagram-api.md)
for the client.

## Threat-Resistance Matrix

The link layer's threat-resistance matrix is consolidated here from
the FMP design document:

| Threat | Mitigation |
| ------ | ---------- |
| Connection exhaustion | Token-bucket rate limit + connection count limit |
| CPU exhaustion (msg1 flood) | Rate limit before crypto operations |
| Replay attacks | Counter-based nonces with sliding window (2048 entries) |
| State confusion | Strict handshake state machine validation |
| Spoofed encrypted packets | Index lookup + AEAD verification |
| Spoofed msg2 | Index lookup + Noise ephemeral key binding |
| Address spoofing | Cryptographic authority, not address-based |
| Session correlation | Index rotation on rekey |
| Inbound exposure on `fips0` | Default-deny nftables baseline (operator opt-in) |
| Sybil identities | Discretionary peering + handshake rate limiting + optional peer ACL |
| Eclipse attack | Diverse peering across independent operators and transports |
| Unauthorized peer admission | Optional `peers.allow` allowlist consulted before handshake |
| Local impersonation via the native datagram API | API disabled by default; when enabled, `fips` group membership is the only gate and must be treated as key access |

See [../design/fips-mesh-layer.md](../design/fips-mesh-layer.md) for
the unauthenticated-attack-surface analysis (only handshake msg1 is
reachable by unauthenticated parties), and
[../design/fips-mesh-operation.md](../design/fips-mesh-operation.md#privacy-considerations)
for the metadata-privacy model and the rejection of onion routing.

## Default Network Exposures by Transport

| Transport | Default Inbound | Default Bind | Opt-in |
| --------- | --------------- | ------------ | ------ |
| UDP | None until `bind_addr` set | `0.0.0.0:2121` typical | Operator sets `transports.udp.bind_addr` |
| TCP | None until `bind_addr` set | None — outbound-only without bind | Operator sets `transports.tcp.bind_addr` |
| Ethernet | Listens on configured interface (raw `AF_PACKET`) | EtherType 0x2121 on selected interface | Per-flag `listen`, `announce`, `auto_connect`, `accept_connections` |
| Tor | None until `directory_service` configured | `127.0.0.1:8443` (loopback only) | Operator sets `transports.tor.directory_service` and configures `HiddenServiceDir` in `torrc` |
| BLE | Off by default | n/a | Operator enables `transports.ble.*` |
| Nostr discovery | Off by default | n/a (relay client, not a listener) | Operator sets `node.rendezvous.nostr.enabled: true` |

The mesh-layer `fips0` interface is reachable from any mesh node that
can route to you, not only direct peers — your direct peers forward
traffic from any reachable mesh node onto your `fips0`. The
default-deny nftables baseline (operator opt-in) is the recommended
way to restrict inbound traffic on `fips0`. See
[../how-to/enable-mesh-firewall.md](../how-to/enable-mesh-firewall.md).

## See also

- [../design/fips-security.md](../design/fips-security.md) — threat
  model and design rationale for the `fips0` baseline
- [../design/fips-mesh-layer.md](../design/fips-mesh-layer.md) — FMP
  link encryption, replay protection, rate limiting
- [../design/fips-session-layer.md](../design/fips-session-layer.md)
  — FSP end-to-end encryption, Noise XK, replay window
- [../how-to/enable-mesh-firewall.md](../how-to/enable-mesh-firewall.md)
  — operator activation and drop-in recipes
- [configuration.md](configuration.md) — full `node.rekey.*`,
  `node.rate_limit.*` parameter tables
- [../how-to/use-the-native-datagram-api.md](../how-to/use-the-native-datagram-api.md)
  — enabling the experimental native datagram API, and what group
  membership grants once it is on
