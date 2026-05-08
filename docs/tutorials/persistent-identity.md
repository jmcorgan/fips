# Make Your Node's Identity Persistent

After completing
[join-the-test-mesh](join-the-test-mesh.md), your daemon is
connected to the public test mesh — but its identity is
ephemeral. Every restart generates a fresh Nostr keypair, so the
npub the rest of the world would use to reach you changes every
time. This tutorial walks through pinning your node to a stable
keypair, locating it on disk, and protecting it.

The whole exercise should take about ten minutes.

## What you'll build

```text
   ┌─────────────────────────────────────────┐
   │  /etc/fips/fips.yaml                    │
   │     node:                               │
   │       identity:                         │
   │         persistent: true   ← this flag  │
   └────────────────┬────────────────────────┘
                    │  daemon reads on start
                    ▼
   ┌─────────────────────────────────────────┐
   │  /etc/fips/fips.key      0600 root:root │
   │  /etc/fips/fips.pub      0644 root:root │
   └─────────────────────────────────────────┘
              your stable nsec / npub
```

After this tutorial your node will have:

- A keypair on disk that the daemon reuses across restarts.
- An npub you can hand to other operators so they can add you to
  their `peers:` list once and have the entry keep working.
- A clear understanding of which file holds the secret and how
  to keep it that way.

## Why a stable identity matters

In FIPS your Nostr keypair *is* your node's identity in the most
literal sense. Several things derive from it:

- Your `fd97:...` mesh address — derived from the public key.
- Your `<npub>.fips` DNS name — the npub itself with `.fips`
  appended.
- Every authenticated connection — Noise XX at the mesh layer,
  XK at the session layer, both prove you hold the matching
  secret key.

> **A keypair, briefly.** Nostr identities are secp256k1
> keypairs. The private half is the `nsec` (a bech32-encoded
> secret key); the public half is the `npub` (a bech32-encoded
> public key). The daemon needs the `nsec` to sign messages and
> complete handshakes; the rest of the world only sees the
> `npub` and uses it as your address.

The daemon supports two ways of holding that keypair:

> **Ephemeral vs. persistent.**
>
> - *Ephemeral* (the default): the daemon mints a brand-new
>   keypair every time it starts, kept only in memory. No
>   long-term secret is ever written to disk; nothing on your
>   machine ties one run to the next; the npub your daemon
>   presents to the network is fresh on every restart. This is
>   the safe-by-default posture — your node has no persistent
>   identity unless you explicitly ask for one.
> - *Persistent*: the daemon reads (or, on first start,
>   generates and writes) a keypair stored at
>   `/etc/fips/fips.key`. The npub stays the same across
>   restarts, reboots, and reinstalls as long as that file is
>   preserved. You take on the cost of protecting an on-disk
>   secret in exchange for being addressable by a stable name.

Persistent identity is a deliberate trade. You give up the
ephemeral default's privacy posture — once your npub is stable,
every connection your node makes is correlatable across time —
and you take on a real secret-management responsibility. In
return you get two things you can't get any other way:

1. **Other operators can reference you by npub.** In
   [join-the-test-mesh](join-the-test-mesh.md) you added
   `test-us01` to your `peers:` list by its npub. That entry
   only works because `test-us01`'s npub doesn't change. If
   anyone is going to reach you the same way, your npub has to
   be just as stable.
2. **Services on your node get a fixed address.** The
   [host-a-service](host-a-service.md) tutorial walks through
   running an HTTP server addressable as
   `<your-npub>.fips`. Clients reach the service by that
   name; if your npub changes on every restart, every
   client's address book breaks.

Both of these are good reasons. Neither is automatic — if your
node is purely a *client*, reaching out to others without
hosting anything itself, you may legitimately want to stay on
the ephemeral default. The rest of this tutorial assumes you've
decided you want a stable identity.

## Step 1: Note your current ephemeral npub

Before changing anything, capture the npub the daemon is using
right now so you can compare against it after the switch.

```sh
sudo fipsctl show status | grep '"npub"'
```

You'll see one line like:

```text
"npub": "npub1abc...xyz"
```

Make a note of it. We expect this to change.

## Step 2: Enable persistent identity in the config

Open `/etc/fips/fips.yaml` and find the `node:` block. The
shipped default has the relevant fragment commented out; make it
look like this:

```yaml
node:
  identity:
    persistent: true
```

Save the file. That is the only configuration change.

The daemon's behavior on the next restart:

- If `/etc/fips/fips.key` already exists, load it and use that
  identity.
- If it does not exist, generate a fresh keypair, write it to
  `/etc/fips/fips.{key,pub}` with the correct file modes, and
  use that.

## Step 3: Restart the daemon

```sh
sudo systemctl restart fips
sudo systemctl status fips
```

Status should show `active (running)` within a couple of
seconds. Confirm the new identity is in use:

```sh
sudo fipsctl show status | grep '"npub"'
```

The npub should be **different** from the one in Step 1 — the
daemon discarded the old in-memory ephemeral keypair and minted
a new one which it has now persisted to disk. From here forward
this is *your* npub.

## Step 4: Locate the keypair on disk

The daemon wrote two files:

```sh
sudo ls -l /etc/fips/fips.key /etc/fips/fips.pub
```

Expect:

```text
-rw------- 1 root root  ... fips.key
-rw-r--r-- 1 root root  ... fips.pub
```

The public file is safe to share — it is your address:

```sh
sudo cat /etc/fips/fips.pub
```

This must match the `npub` reported by `sudo fipsctl show
status`. Hand this string to anyone you want to be reachable
from; they paste it into their own `peers:` block as the `npub:`
field.

The private file is the secret. **Do not** `cat` or paste its
contents anywhere — there is no reason to see it, and any line
of shell history or screen capture that contains it has captured
the secret.

## Step 5: Verify it survives a restart

Restart once more to confirm the daemon is reading `fips.key`
rather than re-generating it:

```sh
sudo systemctl restart fips
sudo fipsctl show status | grep '"npub"'
```

The npub should match Step 3 exactly. If it does not, the daemon
was unable to read `fips.key` (most likely a permission problem)
— see [Troubleshooting](#troubleshooting).

## Step 6: Protect the nsec

`fips.key` is the only thing standing between you and someone
else impersonating your node. The daemon ships it with the right
permissions; the operator's job is to keep them that way.

What that means in practice:

- **Do not loosen the file mode.** `0600` (read/write for owner
  only — here `root`) is correct; `chmod 0644` to "fix" a
  permission error puts the secret on display to every account
  on the host.
- **Do not commit it to source control.** If you maintain
  configuration in a Git repo, exclude `fips.key`; if you use
  ansible-vault or a similar mechanism, encrypt it. `fips.pub`
  may be checked in freely.
- **Do not paste it into chat or email.** Operators sometimes
  share config snippets to demonstrate a setup; redact the
  contents of `fips.key` to a placeholder before doing so.
- **Back it up the way you back up an SSH host key.** Treat the
  file (or its contents) the same way you would treat
  `/etc/ssh/ssh_host_ed25519_key`: encrypted, offline, available
  to recover the *same* identity if the host disappears.

There is no in-protocol "key change" message in FIPS. If
`fips.key` is lost, the npub is lost — your node will come back
up with a new identity and every downstream reference to the
old one will be stale.

## What you've learned

- **Identity = keypair.** Every FIPS node is a Nostr keypair;
  the npub is its address, the nsec is its credential.
- **The flag.** `node.identity.persistent: true` in
  `/etc/fips/fips.yaml` is the difference between ephemeral and
  persistent identity.
- **Where it lives.** `/etc/fips/fips.key` and
  `/etc/fips/fips.pub`, mode `0600` and `0644`, owned
  `root:root`.
- **What to share.** `fips.pub` is public; `fips.key` is not.
- **What it buys you.** A npub other operators can add to their
  `peers:` list once, and that addresses the services your node
  will eventually run.

## Troubleshooting

If the post-restart npub does not match `fips.pub`:

- **Check file permissions.**
  `sudo ls -l /etc/fips/fips.key`. If the mode is not `0600` or
  the owner is not `root:root`, the daemon may have refused to
  read it. Restore with
  `sudo chmod 0600 /etc/fips/fips.key && sudo chown root:root
  /etc/fips/fips.key`.
- **Check the journal.** `sudo journalctl -u fips -n 100` after
  the restart will show one of:
  - `Loaded persistent identity from key file path=...` — good.
  - `Generated persistent identity, saved to key file ...` —
    also good, but only expected on the first start after the
    flag flip.
  - `Using ephemeral identity (new keypair each start)` — the
    config flag was not picked up; re-check the indentation of
    the `persistent: true` line.

If you see `Generated persistent identity...` on every start,
the file is being written but not read on subsequent starts;
this is almost always the same permission/path issue.

## What's next

- **Resolve peer addresses via Nostr.**
  [resolve-peers-via-nostr](resolve-peers-via-nostr.md) walks
  through the smallest useful step toward Nostr-mediated
  discovery: keep your peer entry, drop its hard-coded address,
  and let the daemon look up the current endpoint from public
  Nostr relays. The first of three tutorials covering Nostr
  discovery; advertising your own node and open ambient
  discovery come next.

- **Reach services on other mesh nodes.**
  [reach-mesh-services](reach-mesh-services.md) drives `nc`,
  `traceroute6`, `curl`, and `ssh` at peers by `.fips` name and
  shows that the FIPS data plane is just IPv6 from an
  application's point of view.

- **Host a service of your own.**
  [host-a-service](host-a-service.md) walks through bringing up
  an HTTP server addressable as `<your-npub>.fips`, bound to
  `fips0` so the exposure is mesh-only, behind the mesh
  firewall.

For the alternative provisioning paths — minting a keypair with
`fipsctl keygen` before the daemon ever starts, or importing an
existing Nostr `nsec` — and the key-rotation procedure, see the
operator-style recipe at
[../how-to/persistent-identity.md](../how-to/persistent-identity.md).

For the full identity model:

- [../design/fips-architecture.md](../design/fips-architecture.md)
  — how npubs become `NodeAddr`s and IPv6 ULAs.
