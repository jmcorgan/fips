# FIPS v0.5.1

**Released**: 2026-09-06

v0.5.1 is a maintenance release on the v0.5.x line and it exists for one
reason: **every Linux artifact from v0.3.0 through v0.5.0 installs
cleanly on Debian 12 and Ubuntu 22.04 and then cannot start.** The
package installs, the package manager reports success, and the daemon
fails to load with `GLIBC_2.39 not found`. If you run FIPS on either of
those distributions from a published package, you have never had a
working daemon, and this release is the fix.

It carries two discovery fixes as well, one of them an external
contribution. There is no wire format change and no new configuration.

## At a glance

### Who should upgrade

- **Debian 12 and Ubuntu 22.04, from a package: upgrade.** The daemon on
  those systems has never run. Nothing you can configure works around
  it.
- **Any other Linux: upgrade at your convenience.** Your daemon was
  running, and you gain the two discovery fixes.
- **macOS, Windows, FreeBSD and OpenWrt: the packaging defect never
  affected you**, since it was in how the Linux artifacts were built. You
  do get the two discovery fixes, which are not gated by platform.
- **From source: you were never affected.** A binary you built runs
  against the C library you built it on.

### Before you upgrade

Nothing to do. No configuration key was added, removed or given a new
meaning, and no configuration that loaded under v0.5.0 fails to load
here.

### What changed

- Linux packages and the systemd tarball now install and run on Debian
  12 and Ubuntu 22.04.
- A node no longer relays away the answer to its own lookup.
- A returning copy of a node's own lookup request is no longer counted
  against the peer that delivered it.

## The Linux packaging defect

**What went wrong.** Every Linux artifact from v0.3.0 onward was built
on the newest available runner. That runner's C library turns the
standard library's `pidfd` references into a hard `GLIBC_2.39` version
requirement, instead of the weak, runtime-checked references they are
meant to compile to. The loader refuses an image on that entry alone, so
`fips`, `fipstop` and `fips-gateway` could not start on any system with
an older C library. **`fipsctl` was unaffected**, which is why an
install checked by running a command looked healthy while the daemon was
dead.

**No source code caused the packaging defect and none was changed to fix
it.** The defect was in the build environment. The two discovery fixes
below are this release's only behavioral change, and they are unrelated to
it.

**Why the declared dependency did not stop it.** The `.deb` said it
needed `libc6` with no version, which every glibc satisfies. So a
package whose binaries required 2.39 installed happily on a system with
2.35.

**What is different now.** The Linux artifacts are built in a container
pinned to the oldest supported distribution, declared in
`packaging/build-floor.env`. Every producer runs
`testing/check-glibc-floor.sh` on what it made, so an artifact that
would not load fails the build rather than reaching you. The declared
dependency is derived from the binaries themselves rather than written
by hand, so it states the floor it was actually built against and
re-derives per architecture. One script now produces the Linux
artifacts, and the systemd tarball takes its binaries out of the package
rather than from a second, unchecked set.

**What was measured.** The `.deb` and the tarball were built and floor
checked on x86_64 and aarch64; both architectures carry a 2.34 floor,
which clears the 2.35 the packaging declares. Five distributions install
the package and start the daemon in CI. Separately, a project that
consumes FIPS inside an initramfs reports five machines of five
unlocking an encrypted root over the mesh, including Debian 12 and
Ubuntu 22.04, both of which fell back to a console prompt on v0.5.0.

**What was not measured.** No published v0.5.1 artifact existed when
this was written; the checks above ran against artifacts built by the
same scripts the release workflow uses. Reproducibility was measured
same-machine at v0.4.2 and cross-machine reproducibility has never been
tested.

## Discovery fixes

### A node relayed away the answer to its own lookup

A lookup request is flooded to every tree peer whose bloom filter claims
the target, so a false positive can send a copy into the wider network
and circulate it back to the node that started it. The only identity
test on arrival asked whether the request named this node as the
*target*, which a lookup this node originated never satisfies. The
returning copy was therefore filed as ordinary transit under the node's
own request id. When the target answered, the reply was reverse-path
forwarded to the peer that had looped the request back, the pending
lookup was never satisfied, and discovery reported that its requests
went unanswered while the answers were in fact arriving.

An inbound response is now matched against this node's outstanding
lookups before the transit dedup record, and a returning copy of the
node's own request is dropped rather than recorded, so that id never
enters the transit cache.

**This was a race rather than a hard failure**: a reply that beat the
looped copy found a clean cache and succeeded. It grew likelier as the
bloom fill ratio rose, which means it got worse as a mesh grew.
Contributed by Arjen.

### `req_duplicate` counted something it does not mean

The fix above drops the returning copy, and it first recorded that drop
under the existing `req_duplicate` rejection, whose documented meaning
is that a peer resent a request. A returning copy has a nonzero floor in
healthy operation and rises with the bloom fill ratio, so folding the
two together put a permanent number on a counter an operator reads as
neighbour misbehaviour, and made the two events indistinguishable.

It now has its own rejection reason and counter, `req_own_loopback`,
shown in `fipstop` as "Own Loopback". `req_duplicate` returns to meaning
only what it says.

**If you watch these counters**, expect a new non-zero `Own Loopback` to
appear on a node that originates lookups. That is traffic that was
previously counted elsewhere or not at all, correctly attributed, rather
than a new fault.

## Compatibility

v0.5.1 is wire-compatible with v0.5.0. No frame gains, loses or resizes
a field, so a mixed mesh works and nodes can be upgraded one at a time
with no coordinated restart. The two discovery changes alter what a node
does with a message it already parsed; neither changes what is on the
wire.

The library surface is unchanged. Configuration is unchanged.

## Upgrade notes

**Package upgrade, Debian and Ubuntu.** The usual upgrade replaces the
binaries and restarts the service. On Debian 12 and Ubuntu 22.04 the
daemon will start for the first time, so this is a first start rather
than a restart: check `fipsctl show status` afterwards and expect to see
peer establishment, not a resumed session.

**Check what you actually have.** If you want to confirm the floor of an
installed binary rather than trust the version string:

```text
objdump -T /usr/bin/fips | grep GLIBC_ | sed 's/.*GLIBC_//' | sort -uV | tail -1
```

An artifact from this release prints `2.34) __libc_start_main`. One from
v0.5.0 or earlier prints `2.39) pidfd_spawnp`, which names the symbol that
caused this.

**Rolling upgrade.** No coordination is needed. Upgrade nodes in any
order.

## Getting v0.5.1

- **Linux x86_64 / aarch64**: `.deb` and tarball at the
  [v0.5.1 release page](https://github.com/jmcorgan/fips/releases/tag/v0.5.1).
- **Arch Linux**: `fips` from the AUR.
- **macOS**: `.pkg` at the v0.5.1 release page.
- **Windows**: ZIP at the v0.5.1 release page.
- **FreeBSD (x86_64)**: `.pkg` at the v0.5.1 release page.
- **OpenWrt**: `.ipk` (OpenWrt 24.x and earlier) or `.apk` (OpenWrt 25+)
  at the v0.5.1 release page.
- **From source**: `cargo build --release` from a checkout of the v0.5.1
  tag (Rust 1.94.1 per `rust-toolchain.toml`; `libclang-dev` is a
  required Linux build prerequisite).
- **Nix / NixOS**: `nix build .#fips` from a checkout of the v0.5.1 tag
  builds the binaries from source with the pinned toolchain and no
  manual prerequisites (see the Nix section of `packaging/README.md`).

There is no Android daemon artifact. Android is supported as an embedded
crate.

The full per-commit changelog lives in
[`CHANGELOG.md`](https://github.com/jmcorgan/fips/blob/v0.5.1/CHANGELOG.md).
Issues and discussion at
[github.com/jmcorgan/fips](https://github.com/jmcorgan/fips). Security
reports have a private channel; see
[`SECURITY.md`](https://github.com/jmcorgan/fips/blob/v0.5.1/SECURITY.md).

## Contributors

Thanks to everyone who contributed code, packaging work, bug reports, or
reviews to this release.

- [@jmcorgan](https://github.com/jmcorgan) (Johnathan Corgan): release
  shepherd; the Linux build and floor-checking work, the loopback
  rejection counter, and the install-suite fix that made the defect
  visible instead of hanging.
- [@Origami74](https://github.com/Origami74) (Arjen): the lookup
  originator fix, so a node accepts the answer to its own lookup instead
  of relaying it away
  ([#141](https://github.com/jmcorgan/fips/pull/141)).
