# FIPS v0.2.1

**Released**: 2026-05-11

v0.2.1 is a maintenance release on the v0.2.x line. No new features
and no wire-format changes; operators running v0.2.0 can upgrade in
place. The release rolls up bug fixes and operational hardening for
issues surfaced in v0.2.0 deployments, plus a bloom-filter fill-ratio
validation that protects mesh-size estimates from saturated-filter
inputs.

## At a glance

- 22 commits since v0.2.0, 5 committers plus 2 issue reporters.
- All changes are backwards-compatible with v0.2.0 on the wire.
- Bloom filter fill-ratio validation hardens the FilterAnnounce
  ingress path.
- TreeAnnounce ancestry validation tightened to match the
  spanning-tree specification.
- Signed-tarball + `.deb` artifact workflow added for tagged
  releases; AUR auto-publish on stable tags.

## Behavior changes worth flagging

- **Bloom filter fill-ratio validation** runs on every inbound
  `FilterAnnounce`. Filters whose derived false-positive rate exceeds
  `node.bloom.max_inbound_fpr` (new config field, default `0.05`) are
  rejected silently on the wire, logged at WARN, and counted in a
  new `bloom.fill_exceeded` counter. A rate-limited WARN also fires
  when the local outgoing filter exceeds the cap.
  `BloomFilter::estimated_count` now takes `max_fpr` and returns
  `Option<f64>`, returning `None` for saturated filters; this
  propagates through `compute_mesh_size` into `estimated_mesh_size`.
- **TreeAnnounce ancestry validation** is now run before tree-state
  mutation, enforcing ancestry-self-match, root-single-entry,
  parent-second-entry, and root-is-minimum-NodeAddr. Non-conforming
  announces are rejected with a WARN. Mixed v0.2.0 / v0.2.1 meshes
  may produce WARN log lines on the v0.2.1 side until all peers
  upgrade; behavior is correct, log noise only.

## Notable bug fixes

- **Control socket path detection** in `fipsctl` and `fipstop` now
  checks for the `/run/fips/` directory instead of the socket file
  inside it. Users not yet in the `fips` group get a clear
  "Permission denied" error instead of a misleading "No such file"
  fallback to `$XDG_RUNTIME_DIR`
  ([#30](https://github.com/jmcorgan/fips/issues/30), reported by
  [@Sebastix](https://github.com/Sebastix)).
- **`fd00::/8` routing protected from Tailscale interception.** The
  daemon installs an IPv6 routing-policy rule
  (`ip -6 rule to fd00::/8 lookup main priority 5265`) at TUN setup,
  so Tailscale's table 52 default route can no longer divert mesh
  traffic.
- **Bloom filter routing greedy-tree fallback.** `find_next_hop` no
  longer returns `NoRoute` when the bloom candidate set is non-empty
  but no candidate is strictly closer than the current node; it
  falls through to greedy tree routing instead. Previously, this
  caused dropped packets in topologies where the tree parent was
  closer but not a bloom candidate.
- **Auto-connect peers reconnect after a graceful Disconnect.**
  Previously, a clean upstream shutdown left the auto-connect peer
  orphaned; only the link-dead, decrypt-fail, and peer-restart paths
  scheduled a reconnect
  ([#60](https://github.com/jmcorgan/fips/issues/60), reported by
  [@SwapMarket](https://github.com/SwapMarket)).
- **`fipsctl connect` rejects FIPS mesh addresses** (`fd00::/8`) for
  `udp`, `tcp`, and `ethernet` transports with a clear error message
  instead of echoing success while the daemon silently failed the
  bind with `EAFNOSUPPORT`
  ([#61](https://github.com/jmcorgan/fips/issues/61), reported by
  [@SwapMarket](https://github.com/SwapMarket)).
- **OpenWrt ipk** cross-compiles cleanly again after excluding the
  BLE feature that requires D-Bus, which is unavailable on OpenWrt
  targets.

## Packaging

- **Linux release artifact workflow** builds x86_64 and aarch64
  tarballs and `.deb` packages on `v*` tag push, with SHA-256
  checksums, and publishes them to the GitHub release page.
- **AUR publish workflow** auto-publishes the `fips` PKGBUILD on
  stable `v*` tags.

## Upgrade notes

Operator-actionable items when moving from v0.2.0 to v0.2.1:

- **Bloom filter fill-ratio cap (default 0.05).** Inbound
  `FilterAnnounce` messages whose derived FPR exceeds the cap are
  rejected silently on the wire. Operators with unusually saturated
  filters in the field may want to confirm that the default applies
  cleanly to their deployment; check the new `bloom.fill_exceeded`
  counter if mesh-size estimates drift after upgrade.
- **TreeAnnounce ancestry tightening.** Mixed v0.2.0 / v0.2.1 meshes
  may produce WARN log lines on the v0.2.1 side until all peers
  upgrade. Behavior is correct, log noise only.

## Getting v0.2.1

- **Linux x86_64 / aarch64**: `.deb` and tarball at the
  [v0.2.1 release page](https://github.com/jmcorgan/fips/releases/tag/v0.2.1).
- **Arch Linux**: `fips` from the AUR.
- **OpenWrt**: `.ipk` at the v0.2.1 release page.
- **From source**: `cargo build --release` from a checkout of the
  v0.2.1 tag.

The full per-commit changelog lives in
[`CHANGELOG.md`](../../CHANGELOG.md). Issues and discussion at
[github.com/jmcorgan/fips](https://github.com/jmcorgan/fips).

## Contributors

Thanks to everyone who contributed code or bug reports to this
release.

**Code and packaging**:

- [@jcorgan](https://github.com/jmcorgan): release shepherd, bloom
  fill-ratio validation, auto-connect reconnect fix, `fipsctl`
  mesh-address rejection, control-socket path detection,
  Tailscale-vs-`fd00::/8` routing policy, bloom routing greedy
  fallback, rustfmt baseline.
- [@Origami74](https://github.com/Origami74): OpenWrt ipk
  BLE-feature build fix.
- [@jodobear](https://github.com/jodobear): Linux release-artifact
  workflow and target-aware build scripts.
- [@dskvr](https://github.com/dskvr): AUR publish workflow.
- [@SatsAndSports](https://github.com/SatsAndSports): TreeAnnounce
  semantic validation.

**Issue reports that drove fixes in this release**:

- [@Sebastix](https://github.com/Sebastix): `fipsctl` / `fipstop`
  control-socket path detection
  ([#30](https://github.com/jmcorgan/fips/issues/30)).
- [@SwapMarket](https://github.com/SwapMarket): auto-connect
  reconnect after graceful disconnect
  ([#60](https://github.com/jmcorgan/fips/issues/60)) and
  `fipsctl` mesh-address rejection
  ([#61](https://github.com/jmcorgan/fips/issues/61)).
