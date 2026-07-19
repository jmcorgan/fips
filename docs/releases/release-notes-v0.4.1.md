# FIPS v0.4.1

**Released**: 2026-07-19

v0.4.1 is a maintenance release on the v0.4.x line. It raises the default
antipoison cap on inbound bloom filter announcements, removes a redundant
spanning-tree metric counter, fixes two convergence and path-MTU bugs, and
cuts per-packet CPU in the bloom and identity paths. There is no wire
format change and no new feature surface.

v0.4.1 is wire-compatible with v0.4.0. Nodes can be upgraded one at a time
with no coordinated restart, though one behavior change below is worth
reading before you start a rolling upgrade.

## At a glance

- `node.bloom.max_inbound_fpr` default moves from `0.10` to `0.20`.
- The `parent_switched` metric counter is gone. Use `parent_switches`.
- Spanning tree no longer serves stale coordinates after a parent link is
  lost through peer removal.
- Discovery no longer loosens a path MTU clamp it had correctly tightened.
- Bloom probing and identity operations do measurably less work per call,
  with identical results.

## Behavior changes worth flagging

### The inbound filter FPR cap default doubles again

`node.bloom.max_inbound_fpr` goes from `0.10` to `0.20`. The cap rejects
inbound `FilterAnnounce` frames whose advertised false positive rate
exceeds it. On the fixed 1 KB, k=5 filter, `0.10` corresponds to a fill of
0.631 and roughly 1,630 reachable entries, and the busiest nodes'
aggregates had started reaching that ceiling as the mesh grew. `0.20`
corresponds to a fill of 0.7248 and roughly 2,114 entries.

Be aware that this is the second time in two releases that this default
has doubled, for the same reason both times. That is worth stating plainly
rather than repeating the previous release's framing: raising the cap buys
headroom, it does not fix anything. The real constraint is the fixed 1 KB
filter size, which is a protocol constant. The structural remedy is the v2
filter work, where filter capacity scales with the mesh instead of being
pinned. This release is an interim step to keep legitimate aggregates from
being rejected until that lands. It is not the start of a pattern of
raising the cap once per release, and if you are sizing capacity planning
around this number, plan against the v2 work rather than against a third
raise.

The antipoison property the cap exists for is preserved. A saturated or
deliberately poisoned filter still presents an FPR near 100% and is still
rejected.

**This matters during a rolling upgrade.** A v0.4.1 node accepts a
`FilterAnnounce` with a derived FPR between 0.10 and 0.20; a v0.4.0 node
drops the same frame, and the drop is silent on the wire with no NACK. The
cap also gates the mesh size estimator, which declines to produce a value
when any contributing filter is over the cap. So while a mesh is partly
upgraded, upgraded and not-yet-upgraded nodes can legitimately report
different mesh sizes, or one can report a size while the other reports
unknown. This resolves once every node is on v0.4.1. If you want to avoid
the window entirely, set `node.bloom.max_inbound_fpr: 0.10` explicitly in
your config before upgrading and remove it after the last node is done.

### The `parent_switched` counter is removed

`parent_switched` was incremented on the line immediately before
`parent_switches` at every site and never independently, so the two
counters always held the same value. `parent_switched` is now gone from
the tree metrics, the control socket snapshot, and the `fipstop` tree
view. `parent_switches` remains and is unchanged.

If you scrape the control socket, or have dashboards or alerts referencing
`parent_switched`, point them at `parent_switches`. Anything still asking
for `parent_switched` will find nothing rather than a zero.

## Notable bug fixes

### Stale coordinates after losing a parent through peer removal

When a node's parent link dropped via peer removal, the node correctly
reparented or self-rooted, but skipped the coordinate cache invalidation
that every other position-change path performs. Cached entries for
downstream destinations kept the node's old coordinate prefix. This did
not self-correct the way a stale cache entry normally would: routing
access refreshes an entry's TTL, so an entry that was actively being
routed through never expired, and was only fixed by an unrelated fresh
insert. Both invalidation classes now run on this path, matching the
loop-detection branch.

### Discovery could loosen a tightened path MTU clamp

An originator handling a `LookupResponse` overwrote its cached path MTU
unconditionally. If a reactive `MtuExceeded` or `PathMtuNotification` had
already taught it a tighter value, a later, looser discovery estimate
would clobber that and re-loosen the clamp, risking a return to dropped
oversized packets. The cached and received values are now compared and the
tighter one is kept.

## Upgrade notes

This is a drop-in upgrade from v0.4.0 with no wire format change, no
config migration, and no coordinated restart. Upgrade nodes in whatever
order you like.

Two things to do rather than assume:

1. If you monitor `parent_switched`, move to `parent_switches` before
   upgrading, or your dashboards will go blank rather than error.
2. During the rolling window, expect upgraded and not-yet-upgraded nodes
   to potentially disagree about mesh size, per the FPR cap section above.
   This is expected and self-resolves. Do not chase it as a bug unless it
   persists after every node reports `0.4.1`.

If you have pinned `node.bloom.max_inbound_fpr` explicitly in your config,
your setting is honored and nothing changes for you. The change only
affects nodes taking the default.

Downgrading to v0.4.0 is supported and needs no special handling.

## Getting v0.4.1

- **Linux x86_64 / aarch64**: `.deb` and tarball at the
  [v0.4.1 release page](https://github.com/jmcorgan/fips/releases/tag/v0.4.1).
- **Arch Linux**: `fips` from the AUR.
- **macOS**: `.pkg` at the v0.4.1 release page.
- **Windows**: ZIP at the v0.4.1 release page.
- **OpenWrt**: `.ipk` (OpenWrt 24.x and earlier) or `.apk` (OpenWrt 25+)
  at the v0.4.1 release page.
- **From source**: `cargo build --release` from a checkout of the v0.4.1
  tag (Rust 1.94.1 per `rust-toolchain.toml`; `libclang-dev` is a
  required Linux build prerequisite).
- **Nix / NixOS**: `nix build .#fips` from a checkout of the v0.4.1 tag
  builds the binaries from source with the pinned toolchain and no manual
  prerequisites (see the Nix section of `packaging/README.md`).

The full per-commit changelog lives in
[`CHANGELOG.md`](../../CHANGELOG.md). Issues and discussion at
[github.com/jmcorgan/fips](https://github.com/jmcorgan/fips).

## Contributors

Thanks to everyone who contributed code, packaging work, bug reports, or
reviews to this release.

- [@jcorgan](https://github.com/jmcorgan): release shepherd, spanning-tree
  and discovery fixes, bloom and identity performance work, antipoison cap
  change, and testing.
