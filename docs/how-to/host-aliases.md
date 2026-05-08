# Use Shortnames Instead of Long Npubs

A FIPS node's canonical address is `<npub>.fips`. The npub is
63 characters of bech32 — fine for the daemon, awkward to type
or fit in a docs example. The local DNS resolver consults a
host map before falling back to direct-npub resolution, so
short names like `test-us01.fips` work as substitutes wherever
`<npub>.fips` would.

This guide covers the two ways to populate that map and when
to use which.

## When to use which

Two independent mechanisms feed the same DNS responder:

| Mechanism | Source | Scope | Reload |
|-----------|--------|-------|--------|
| Hosts file | `/etc/fips/hosts` | Node-local, intended for shared rosters | Auto on mtime change |
| Peer alias | `alias:` field on a `peers:` entry | Node-local, scoped to configured peers | Daemon restart |

Pick the hosts file when:

- The shortname refers to a peer your operator-team agrees to
  call by that name across machines (the public test mesh
  ships this way).
- You want the destination's name to resolve in DNS or appear
  in `fipsctl show peers` display even though it isn't in your
  `peers:` block — e.g., a mesh node you reach transitively
  through your direct peers. The hosts-file entry is for name
  resolution and display only; it does not stand in for the
  npub a peer-config entry requires.

Pick the peer alias when:

- The shortname is just a label *you* use locally for a peer
  that's already in your `peers:` block.
- You want the alias to live with the rest of the peer config
  (one place to look) rather than in a separate file.

The two coexist. If both reference the same shortname,
`/etc/fips/hosts` wins — the file is treated as the
authoritative shared roster.

## What ships in the default `/etc/fips/hosts`

The installer drops `/etc/fips/hosts` populated with the
public test mesh roster:

```text
test-us01      npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98
test-us02      npub10yffd020a4ag8zcy75f9pruq3rnghvvhd5hphl9s62zgp35s560qrksp9u
test-us03      npub136yqae6na688fs75g95ppps3lxe07fvxefj77938zf47uhm6074sxw8ctm
test-us03-next npub15m6c4ghuegx4pcde6tra8f7smn8vfv2wundyxwhkjynuerkrzmgsy09sh3
test-us04      npub1gd7ye2qp2lphhzx75fynnjzaxx4dqanddecet0wtt5ss5ek8h9ps62wdkf
test-de01      npub1260n42s06vzc7796w0fh3ny7zcpw6tlk4gq3940gmfrzl5c9pv2s3657q8
test-es01      npub17lpmzulpc98d8ff727k6e98atxn3phzupzsqqwe54ytduym747ws4tw5zm
test-uk01      npub1u0z26dc4qeneu5rvwvmpfhtwh3522ed6rlgxr9jarrfnjrc6ew4qxjysrs
```

These resolve out of the box — `ping6 test-us01.fips` works
even before you've added any peer to your config, as long as
the destination is reachable through your mesh links.

If you don't intend to interact with the public test mesh,
the entries are safe to comment out or delete. They are
plain hosts-file lines, not protocol participants — removing
them only changes name resolution on your machine.

## Add an entry to `/etc/fips/hosts`

Append a line to `/etc/fips/hosts`:

```text
my-laptop     npub1abc...xyz
```

Format rules:

- One hostname and one npub per line, separated by
  whitespace.
- Hostnames are lowercase letters, digits, and hyphens; max
  63 characters.
- Comments start with `#` and continue to end of line; blank
  lines are ignored.
- On duplicate hostnames, the last entry wins.

The daemon picks up the change on the next DNS query — no
restart required (the file's mtime is checked on each query).
Verify:

```sh
dig my-laptop.fips AAAA +short
```

Expect one `fd97:...` AAAA record.

`/etc/fips/hosts` is shipped as a dpkg conffile (and the AUR
equivalent), so package upgrades preserve your edits. The
file is `0644 root:root` — readable by anyone, writable by
root.

## Add a peer alias

In `/etc/fips/fips.yaml`, set the `alias:` field on the peer
entry:

```yaml
peers:
  - npub: "npub1abc...xyz"
    alias: "my-laptop"
    addresses:
      - transport: udp
        addr: "192.0.2.10:2121"
    connect_policy: auto_connect
```

Restart the daemon for the alias to take effect:

```sh
sudo systemctl restart fips
dig my-laptop.fips AAAA +short
```

The alias also shows up in `fipsctl show peers` `display_name`
column, so log entries and CLI output reference the peer by
shortname instead of truncated npub.

## Resolution order

When the DNS responder receives a query for `<name>.fips`:

1. **Hosts file lookup.** If `<name>` matches an entry in
   `/etc/fips/hosts`, the daemon returns the AAAA record
   derived from that entry's npub.
2. **Peer alias lookup.** If `<name>` matches the `alias`
   field on a configured peer, return that peer's AAAA.
3. **Direct npub resolution.** If `<name>` is itself a valid
   bech32 npub (the canonical 63-char `npub1...` form), the
   daemon returns the AAAA derived from that npub directly.
4. **NXDOMAIN.** If none of the above match, the query
   returns no answer.

The order means the hosts file overrides peer aliases on
conflict. That's deliberate: the file represents
operator-shared naming, the peer alias is a node-local label.

## Cross-references and ACLs

Aliases interact with the peer ACL — if you maintain
`peers.allow` or `peers.deny` lists keyed on hostnames rather
than npubs, those names go through the same hosts-file
resolution. See
[../reference/security.md](../reference/security.md) for the
ACL format and the alias-resolution semantics.

`fipsctl connect` and `fipsctl disconnect` accept a shortname
where they expect an npub. Resolution for these commands goes
through `/etc/fips/hosts` only — peer-config `alias:` entries
are not loaded by `fipsctl`, so a shortname that exists only as
a peer alias must still be referenced by full npub on the CLI.
See [../reference/cli-fipsctl.md](../reference/cli-fipsctl.md).

## See also

- [../reference/configuration.md § Host Mapping](../reference/configuration.md#host-mapping)
  — minimal reference entry for the host-map mechanism.
- [../reference/cli-fipsctl.md](../reference/cli-fipsctl.md)
  — `fipsctl` arguments that accept shortnames.
- [../reference/security.md](../reference/security.md)
  — peer ACL semantics with aliased entries.
- [../design/fips-ipv6-adapter.md](../design/fips-ipv6-adapter.md)
  — the DNS resolver design and the npub-to-IPv6 derivation.
