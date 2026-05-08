# Provision a Persistent Identity

A FIPS node's identity is a Nostr keypair. Its public key (npub)
determines the node's `fd00::/8` mesh address; peers and configs
reference the node by that npub. Out of the box the daemon generates
a fresh identity on every start (`node.identity.persistent: false`),
which is fine for one-off testing but useless when other nodes need
to refer to this one across restarts.

This guide covers the three ways to give a node a stable identity.
For the configuration keys involved, see
[../reference/configuration.md](../reference/configuration.md).

> **First time?** If you have just installed FIPS and want a
> hand-held walkthrough of the package-default path (set
> `persistent: true`, restart, observe the keys land), the
> [persistent-identity tutorial](../tutorials/persistent-identity.md)
> is the gentler entry point. This guide assumes an operator
> picking among Options A/B/C for a deployment.

## When to use

Use a persistent identity for any node that:

- Other operators reference by npub (in their `peers` lists, `hosts`
  files, or ACL allow-lists).
- Acts as a discoverable bootstrap or rendezvous (Nostr advert,
  static peer entry, gateway).
- Is expected to keep its `fd00::/8` mesh address across restarts.

Stay with the ephemeral default for throw-away clients, sandbox
nodes, and tests where you actively want a fresh identity per run.

## Option A: Let the package do it

The Debian/Ubuntu `.deb` and the Arch `fips` AUR package both ship a
default `/etc/fips/fips.yaml` with `node.identity.persistent` left as
the upstream default (false), so the daemon writes a fresh keypair to
`/etc/fips/fips.{key,pub}` on every start until you set
`persistent: true`. To pin the current keypair:

1. Install the package and start the daemon once so it generates
   `fips.key` / `fips.pub`:

   ```sh
   sudo systemctl start fips
   sudo systemctl status fips     # confirm it came up
   ```

2. Edit `/etc/fips/fips.yaml` and set:

   ```yaml
   node:
     identity:
       persistent: true
   ```

3. Restart the daemon and verify the identity is reused:

   ```sh
   sudo systemctl restart fips
   fipsctl show status | grep -E '"npub"|"node_addr"'
   cat /etc/fips/fips.pub
   ```

   The npub printed by `fipsctl show status` should match
   `/etc/fips/fips.pub` and remain stable across subsequent restarts.

The package's `postinst` script does **not** generate the keypair —
the daemon does, on first start. This means the keypair is only
present after the first successful daemon start. If the daemon never
came up cleanly (config error, permission problem), the key files
will be missing.

### File layout and permissions

| Path | Mode | Owner | Contents |
| ---- | ---- | ----- | -------- |
| `/etc/fips/fips.key` | `0600` | `root:root` | Bech32 `nsec` (one line). |
| `/etc/fips/fips.pub` | `0644` | `root:root` | Bech32 `npub` (one line). |

Both files live next to the highest-priority `fips.yaml` the daemon
loaded. For non-systemd installs that use a different config path,
the key files are placed in that config's directory.

## Option B: Generate manually

For from-source installs, custom config paths, or any deployment
where you want to mint the keypair before the daemon ever runs.

### With `fipsctl keygen`

```sh
sudo fipsctl keygen --dir /etc/fips
```

This writes `/etc/fips/fips.key` (mode `0600`) and
`/etc/fips/fips.pub` (mode `0644`), prints the new npub on stderr,
and reminds you to set `persistent: true`. Add `--force` to overwrite
an existing `fips.key`. Add `--stdout` to print `nsec` then `npub`
to stdout instead of writing files.

To put the keypair in a non-default directory (e.g., a per-deployment
config tree), pass `--dir` and point your `fips.yaml` search at the
matching directory.

### Without the daemon installed

If you cannot run `fipsctl` (e.g., scripting on a build host), any
nostr-tools-equivalent that emits a bech32 `nsec` works. Write the
nsec to `fips.key` (mode `0600`) and the corresponding `npub` to
`fips.pub` (mode `0644`).

### Hooking the keypair into the config

```yaml
node:
  identity:
    persistent: true
```

`persistent: true` plus a `fips.key` next to the loaded config is the
intended steady-state setup.

## Option C: Provision from an existing nsec

To migrate an existing Nostr identity into a FIPS node — for example,
re-using a personal npub for a node you operate.

1. Obtain the bech32 `nsec` for the identity.
2. Write it to the config-adjacent key file:

   ```sh
   sudo install -m 0600 -o root -g root /dev/null /etc/fips/fips.key
   sudo bash -c 'printf "%s\n" nsec1... > /etc/fips/fips.key'
   ```

3. Derive the matching `npub` and write `fips.pub`:

   ```sh
   # compute the npub with any nostr tool, then:
   sudo bash -c 'printf "%s\n" npub1... > /etc/fips/fips.pub'
   sudo chmod 0644 /etc/fips/fips.pub
   ```

4. Set `persistent: true` and restart:

   ```yaml
   node:
     identity:
       persistent: true
   ```

   ```sh
   sudo systemctl restart fips
   fipsctl show status | grep '"npub"'
   ```

The reported npub should match the one you wrote to `fips.pub`.

## Verifying

The daemon prints the resolved identity at startup; the same value is
queryable via the control socket:

```sh
fipsctl show status | jq '{npub, node_addr, ipv6_addr}'
cat /etc/fips/fips.pub
```

The `npub` field of `show status` and the contents of `fips.pub`
should match. The `node_addr` is the SHA-256 prefix used internally
by FMP/FSP; the `ipv6_addr` is the routable `fd00::/8` mesh address
derived from the node addr. Together they are stable for the lifetime
of the keypair.

The journal also records the source on every start:

```text
INFO Loaded persistent identity from key file path=/etc/fips/fips.key
```

(`Generated persistent identity, saved to key file` on the first
start; `Using ephemeral identity (new keypair each start)` when
persistence is off.)

## Rotating

Key rotation is a destructive operation: every cached
`(node_addr → npub)` mapping on every other node points at the old
key, every Nostr advert and every static peer entry references the
old npub, and every existing FSP session was authenticated under the
old keypair. There is no in-protocol "key change" message.

To rotate:

1. Stop the daemon.

   ```sh
   sudo systemctl stop fips
   ```

2. Remove the existing key files.

   ```sh
   sudo rm /etc/fips/fips.key /etc/fips/fips.pub
   ```

3. Start the daemon. With `persistent: true`, the daemon generates a
   new keypair and writes new `fips.key` / `fips.pub`.

   ```sh
   sudo systemctl start fips
   cat /etc/fips/fips.pub   # the new npub
   ```

4. Update every downstream reference: peer configs that name this
   node by npub, `hosts` files, ACL allow-lists, Nostr adverts
   pinned by other operators.

There is no recovery from a lost `fips.key` — the npub is gone with
the secret. Treat key rotation as a coordinated event; do not rotate
production identities ad hoc.

## See also

- [../reference/configuration.md](../reference/configuration.md) —
  `node.identity.*` keys.
- [../reference/cli-fipsctl.md](../reference/cli-fipsctl.md) —
  `fipsctl keygen`.
- [../design/fips-architecture.md](../design/fips-architecture.md) —
  identity model, npub-to-NodeAddr derivation.
