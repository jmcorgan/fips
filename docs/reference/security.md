# Security Reference

Consolidated security reference covering the nftables baseline, peer
ACL file format, cryptographic primitives, rekey defaults, replay
window, filesystem permissions, threat-resistance matrix, and default
network exposures per transport. For the threat-model design and
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
| Curve | secp256k1 | FMP XX, FSP XX, Schnorr signatures |
| Diffie-Hellman | ECDH on secp256k1 (x-only normalized) | Noise XX (both layers) |
| AEAD | ChaCha20-Poly1305 | FMP link encryption, FSP session encryption |
| Hash | SHA-256 | NodeAddr derivation, Noise transcript |
| Key derivation | HKDF-SHA256 | Noise key schedule |
| Signatures | secp256k1 Schnorr | TreeAnnounce, LookupResponse proof, Nostr adverts |
| Noise pattern (link) | `Noise_XX_secp256k1_ChaChaPoly_SHA256` | FMP link layer (XX with negotiation payload) |
| Noise pattern (session) | `Noise_XX_secp256k1_ChaChaPoly_SHA256` | FSP session layer (XX with negotiation payload) |

These choices align with the Nostr cryptographic stack
(secp256k1 + ChaCha20-Poly1305 + SHA-256) and the NIP-44 encrypted
messaging standard.

## Rekey Defaults

Both link-layer and session-layer Noise sessions rekey under one of
two triggers, configurable under `node.rekey.*`:

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `enabled` | `true` | Master switch. |
| `after_secs` | `120` | Time-based rekey threshold. |
| `after_messages` | `65536` | Message-count rekey threshold. |

In addition to the configurable triggers, the daemon retains the old
session keys for a fixed **10-second drain window** after each
cutover (compile-time constant `DRAIN_WINDOW_SECS` in
`src/node/handlers/rekey.rs`). Rekey rotates the Noise key schedule
and the session indices; old session keys are kept in
`previous_session` for the drain window so in-flight packets
encrypted under the old keys still decrypt.

## Replay Window

Both layers use explicit per-packet counters with a sliding bitmap
window for replay protection. The bitmap is **2048 entries** at both
layers — large enough to accommodate UDP reordering and packet loss
without false-positive replay rejection. Counters older than the
window are rejected. The same `ReplayWindow` and
`decrypt_with_replay_check()` implementation is used at both the FMP
and FSP layers.

## Peer ACL

Mesh-level ACL files at `/etc/fips/peers.allow` and
`/etc/fips/peers.deny` give the operator allowlist/blocklist control
over which npubs may complete the FMP Noise XX link handshake.

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
| `/etc/fips/fips.yaml` | root:root | `0644` | Daemon configuration (dpkg conffile). |
| `/etc/fips/fips.nft` | root:root | `0644` | nftables baseline (dpkg conffile). |
| `/etc/fips/fips.d/` | root:root | `0755` | Operator drop-in directory. |
| `/etc/fips/hosts` | root:root | `0644` | Optional hostname → npub map (dpkg conffile). |
| `/etc/fips/peers.allow` | root:root | `0644` | Optional peer allowlist. |
| `/etc/fips/peers.deny` | root:root | `0644` | Optional peer denylist. |
| `/run/fips/control.sock` | root:fips | `0770` | Control socket (members of `fips` group can use `fipsctl`). |
| `/run/fips/` | root:fips | `0750` | Control socket parent directory. |

Adding a user to the `fips` group grants `fipsctl` access without
requiring root. The daemon `chown`s the control socket and its parent
directory at bind time.

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
| Nostr discovery | Off by default | n/a (relay client, not a listener) | Operator sets `node.discovery.nostr.enabled: true` |

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
  — FSP end-to-end encryption, Noise XX, replay window
- [../how-to/enable-mesh-firewall.md](../how-to/enable-mesh-firewall.md)
  — operator activation and drop-in recipes
- [configuration.md](configuration.md) — full `node.rekey.*`,
  `node.rate_limit.*` parameter tables
