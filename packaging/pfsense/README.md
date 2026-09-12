# FIPS pfSense packaging

Builds a `.pkg` that installs FIPS on pfSense: `fips`, `fipsctl`,
`fipstop`, a boot script pfSense actually runs, and helpers that wire
the `.fips` zone into the DNS Resolver. `fips-gateway` is excluded (its
NAT backend is nftables, Linux-only; pfSense has pf for that).

This is **not a Netgate-supported package** and has no GUI. Netgate
[documents third-party packages as unsupported][netgate-freebsd-pkg]
and warns they can break upgrades; treat it accordingly.

[netgate-freebsd-pkg]: https://docs.netgate.com/pfsense/en/latest/recipes/freebsd-pkg-repo.html

## Maintenance and reports

This package is maintained by **fr34aky** (via the project's issue
tracker). pfSense-specific problems — a boot script that does not start,
DNS wiring, an upgrade that misbehaves — are best reported there; the
package manifest's maintainer field points at the project, so reports
reach it either way. The ABI-to-product table below tracks Netgate's
releases and needs updating when a new pfSense version ships or an old
one goes end-of-life; that is part of maintaining this package.

## Why this is separate from `packaging/freebsd/`

pfSense is FreeBSD underneath, but the FreeBSD package does not work
here — not "works worse", does not work — in three ways that all fail
silently:

| | FreeBSD package | pfSense |
|---|---|---|
| Boot | `rc.d/fips`, an `rc.conf`-gated rc.subr service | pfSense's `rc.start_packages` globs `/usr/local/etc/rc.d/*.sh` and runs each as `<script> start`, at boot and again on a WAN IP change. A suffixless script is never run; the `.sh` script must make a re-run a quiet no-op. |
| DNS | drop-in at `/var/unbound/conf.d/fips.conf` | `unbound.conf` is generated from `config.xml` and includes no `conf.d` directory. The drop-in is simply never read. |
| Responder bind | `::1` | pfSense writes `do-ip6: no` unless "Allow IPv6" is set, and then cannot reach `[::1]` at all. This package binds `127.0.0.1`. |

So: `fips.sh` instead of `fips`, DNS Resolver custom options instead of
a drop-in, and knobs in `/usr/local/etc/fips/fips.conf` instead of
`/etc/rc.conf`.

The mechanics that are *not* different are shared rather than copied:
`packaging/common/pkg-lib.sh` holds version derivation, the stage
layout, the manifest fields both packages agree on, the @sample
install-if-absent scripts, and `pkg create` itself. Both builders
source it. What stays per-package is only what the two systems
genuinely disagree about — boot, DNS, linkage, ABI and naming — since
folding those into one file behind flags would hide the differences
this table exists to explain.

## Which pfSense this matches

`pkg` refuses a package whose ABI does not match the running system, in
**both** the FreeBSD major and the architecture. Netgate's ARM
appliances are `aarch64`, so "which pfSense" is two questions, not one.
Ask the appliance rather than guessing:

```sh
pkg config abi        # e.g. FreeBSD:16:aarch64
uname -m
```

The supported releases, from [Netgate's version
table](https://docs.netgate.com/pfsense/en/latest/releases/versions.html)
as of September 2026:

| Release | FreeBSD base | pkg ABI | Build host needed |
|---|---|---|---|
| pfSense CE 2.8.1 | 15.0-CURRENT | `FreeBSD:15:amd64` | FreeBSD 15, amd64 |
| pfSense CE 2.9.0 | 16.0-CURRENT | `FreeBSD:16:amd64` | FreeBSD 16, amd64 |
| pfSense Plus 26.03.1 / 26.07, Intel | 16.0-CURRENT | `FreeBSD:16:amd64` | FreeBSD 16, amd64 |
| pfSense Plus 26.03.1 / 26.07, ARM | 16.0-CURRENT | `FreeBSD:16:aarch64` | FreeBSD 16, **aarch64** |

CE has only ever shipped for amd64; Netgate has said there are no plans
for an ARM CE image. Plus 24.x and 25.x are end-of-life and deliberately
not in the build's table: a package named for an unsupported release
invites installing it there. The base moves between releases — CE 2.9
moved to FreeBSD 16 in August 2026 — so check the table before building.

The filename names the **pfSense product(s)**, not the FreeBSD ABI —
`fips-<version>-pfsense-<products>-<arch>.pkg` — because that is what
someone choosing a download knows. You know you run "Plus 26.03 on a
4200"; you do not necessarily know that means `FreeBSD:16:aarch64`.

One ABI can serve more than one product. CE 2.9 and Plus 26.x on Intel
are both `FreeBSD:16:amd64` and the artifact is byte-identical, so its
name carries both: `…-pfsense-ce2.9-plus26-amd64.pkg`. Architecture
alone would not do either way — CE 2.8 and CE 2.9 are both `amd64` and
`pkg` refuses each on the other's base.

The mapping is ABI → products, declared in one place in `build-pkg.sh`,
because the ABI is what gets built and the products are what people look
for. The build **refuses** an ABI that no supported release runs on
(`FreeBSD:15:aarch64`: only end-of-life Plus versions), and `--product`
is an assertion rather than a selector: pass it to say "I believe I am
building for CE 2.8", and the build refuses if that product does not run
on the ABI. The ABI stays in the manifest, where `pkg` reads it, and the
products in a `pfsense_products` annotation, so a renamed file can still
identify itself:

```sh
pkg info -A -F <file>.pkg   # pfsense_products: ce2.9 plus26
pkg info -F <file>.pkg      # Architecture: FreeBSD:16:amd64
```

| Artifact | Installs on |
|---|---|
| `…-pfsense-ce2.8-amd64.pkg` | pfSense CE 2.8.1 |
| `…-pfsense-ce2.9-plus26-amd64.pkg` | pfSense CE 2.9.0, and Plus 26.x on Intel |
| `…-pfsense-plus26-aarch64.pkg` | pfSense Plus 26.x on ARM |

Which of those can be built, and with what provenance, differs — and the
difference decides which may be published:

| Artifact | linkage | toolchain pin | CI |
|---|---|---|---|
| `…-pfsense-ce2.8-amd64.pkg` | static | honoured | built + checked, workflow artifact |
| `…-pfsense-ce2.9-plus26-amd64.pkg` | static | honoured | not built — CI has no FreeBSD 16 host |
| `…-pfsense-plus26-aarch64.pkg` | dynamic | **not** honoured | not built — build it yourself |

No pfSense package is attached to a release. It is built and checked in
its own CI job (so a pfSense-only failure reds that job without blocking
the FreeBSD asset) and kept as a 30-day workflow artifact, until one has
been installed on a real pfSense box.

The two absences are not the same. The FreeBSD 16 Intel package builds
cleanly with the pinned compiler and links statically, so it is
releasable in principle and waits only on a FreeBSD 16 amd64 builder;
the CI VM is 15.1 and `vmactions/freebsd-vm` offers nothing newer, and
FreeBSD 16 is not released, so such a builder means a moving
16.0-CURRENT snapshot. Until then, CI builds and checks only the package
for the *older* supported CE release, as a workflow artifact. ARM cannot
honour the pin at all, so it
stays build-it-yourself regardless of infrastructure.

### There is no cross-compiling out of this

The build host must genuinely be the target's architecture. Two reasons,
and the first is the one that wastes an afternoon:

- **`--abi` only relabels.** It changes the string `pkg` checks, not the
  binaries. A package labelled `FreeBSD:16:aarch64` full of x86-64
  binaries installs perfectly and then cannot exec.
  `testing/check-pfsense-pkg.sh` compares the label against the real
  binaries for exactly this reason, and fails the package.
- **Rust ships no toolchain for FreeBSD/ARM, in either direction.**
  `rustup target add aarch64-unknown-freebsd` on an x86-64 FreeBSD host
  fails with "no prebuilt artifacts available for target" — only
  `i686-unknown-freebsd` and `x86_64-unknown-freebsd` are offered — and
  rustup has no installer for the platform natively either. What makes a
  native aarch64 builder the path of least resistance is not rustup but
  the ports Rust (`pkg install rust`), with the pin consequences below.

`build-pkg.sh --target <triple>` exists for a builder that is already
the right architecture (it reads binaries from `target/<triple>/release`
and cross-checks the triple against `--abi`). It does not conjure a
toolchain that Rust does not distribute.

### ARM builds are build-it-yourself, and are not released

**No aarch64 package is published as a release artifact.** Build one
yourself with the recipe above, on your own aarch64 FreeBSD 16 host.

The reason is the toolchain, not the architecture. `rust-toolchain.toml`
pins an exact compiler, and every published artifact for every other
platform is built with it. On aarch64 FreeBSD that is impossible:

```
$ rustup target add aarch64-unknown-freebsd
error: toolchain '1.94.1-x86_64-unknown-freebsd' has no prebuilt
       artifacts available for target 'aarch64-unknown-freebsd'

$ (on an aarch64 FreeBSD host)
error: installer for platform 'aarch64-unknown-freebsd' not found
```

So an ARM build uses the ports Rust, and the ports cargo ignores
`rust-toolchain.toml` outright. Publishing such a package alongside the
others would quietly imply a provenance it does not have.

The alternatives were considered and rejected: `RUSTC_BOOTSTRAP=1` with
`-Z build-std` nominally satisfies the pin, but only by disabling the
stable/unstable boundary and rebuilding `std` through a path upstream
does not support — a *less* visible deviation than a different version
number, for a daemon that terminates encrypted tunnels on a firewall.
Building rustc 1.94.1 from source is a multi-hour bootstrap that still
yields an unofficial, unverifiable compiler.

Every package records what produced it, so this is answerable from the
artifact rather than from whoever remembers building it:

```sh
pkg info -A fips
# built_with     : rustc <ports version>
# toolchain_pin  : 1.94.1
# pin_honoured   : no          <- not a release artifact
# linkage        : static
# rust_pkg       : rust-<ports version>
```

`build-pkg.sh` prints a loud notice whenever the compiler is not the
pinned one, and refuses outright below the edition-2024 floor (1.85).
`testing/check-pfsense-pkg.sh` fails a package that has lost these
annotations, and flags `pin_honoured: no` in its output.

### FreeBSD 16 is not released

pfSense CE 2.9 and Plus 26.x are built from FreeBSD **16.0-CURRENT**, a development
branch; 16.0-RELEASE does not exist yet. So a FreeBSD 16 builder means a
[16.0-CURRENT snapshot](https://download.freebsd.org/snapshots/), not a
release image — and `vmactions/freebsd-vm`, which this repo's CI uses,
only goes up to 15.1.

That makes base-library drift a real risk rather than a theoretical one:
Netgate's `16.0-CURRENT@<hash>` and a FreeBSD snapshot from another date
are different trees, and a binary can reference a symbol the appliance's
`libc` does not export. It installs and then fails to start. If `fips`
exits immediately with a linker error, that is this. Build from a
snapshot close to the appliance's base, and check what the binary
actually needs:

```sh
pkg info -F <the .pkg> | grep -A5 "Shared Libs"   # on the build host
ldd /usr/local/bin/fips                           # on the appliance
```

## Build

```sh
gmake -C packaging pfsense        # or:
./packaging/pfsense/build-pkg.sh            # cargo build --release + pkg create
./packaging/pfsense/build-pkg.sh --no-build # package existing release binaries
./packaging/pfsense/build-pkg.sh --dynamic  # link against libc.so.7 (see below)
```

Output: `deploy/fips-<version>-pfsense-<products>-<arch>.pkg`. Validate it before
shipping it anywhere:

```sh
./testing/check-pfsense-pkg.sh deploy/fips-<version>-pfsense-ce2.8-amd64.pkg
```

### Static linking is the default

Unlike every other platform's package, this one links statically unless
you ask otherwise. The reason is specific to pfSense: **it runs a
FreeBSD base you cannot obtain.** Netgate builds Plus from a
16.0-CURRENT snapshot of their own, and download.freebsd.org keeps only
the last two CURRENT builds — so there is usually no way to build
against the appliance's libraries even if you want to.

In practice the build host's `libc` ends up *newer* than the
appliance's, which is the direction that breaks: the binary references a
versioned symbol the appliance does not export, installs cleanly, and
then will not start. A dynamic package needs `libc.so.7`, `libm.so.5`,
`libthr.so.3` and `libgcc_s.so.1` to agree with it; a static one
declares no shared libraries at all. What is left is the kernel syscall
ABI, which is stable within a FreeBSD major.

That is also why a static package survives a pfSense firmware upgrade's
change of base, where a dynamic one is pinned to the image it was built
against.

It is viable here because nothing in this codebase uses `dlopen` or
`libloading`, and FreeBSD compiles `files`/`dns` resolution into `libc`
— so a static binary still resolves hostnames. (This is where static
*glibc* would defeat you; FreeBSD is not glibc.) Verified end to end: a
static build resolves a peer hostname, completes the Noise handshake,
joins the spanning tree and answers `.fips` queries.

`crt-static` is a request a target may silently ignore, so
`build-pkg.sh` checks the produced binaries and fails if any came out
dynamic — shipping a dynamic binary while believing it static would
quietly reinstate the exposure this default exists to remove. The
package records which it is, in the `linkage` annotation.

**aarch64 is the exception, and the build refuses rather than
downgrades.** A statically linked aarch64 FreeBSD binary faults at
`addr=0x0` where `posix_spawn` should be, so the daemon dies the
first time it shells out — `sysctl`, from `is_ipv6_disabled()` at the
top of `TunDevice::create`. It presents as a TUN bug, and with
`tun.enabled: false` the daemon never spawns anything and looks
healthy. The same trace on static amd64 reaches `rfork(RFSPAWN)` and
spawns normally, so this is the architecture, not static linking.
ARM builds must pass `--dynamic`; `ldd` on the appliance then tells
you whether the drift this default exists to avoid is real.

Use `--dynamic` if you specifically want the smaller binaries and know
your build host's base matches the appliance's.

## Install

Copy the package to the firewall and, as root:

```sh
pkg add ./fips-<version>-pfsense-ce2.8-amd64.pkg
vi /usr/local/etc/fips/fips.yaml          # identity and peers
/usr/local/etc/rc.d/fips.sh start
fipsctl show status
```

To upgrade an existing install, use `pkg install ./<file>.pkg`, not
`pkg add`: only `pkg install` runs the upgrade path (the old package's
pre-deinstall then the new post-install, with `PKG_UPGRADE=true`), which
stops the daemon before its binary is replaced and starts it after.
`pkg add` on an installed package refuses without `-f` and, with `-f`,
reinstalls without those hooks — so follow a `pkg add -f` with
`/usr/local/etc/rc.d/fips.sh restart` by hand. `pkg upgrade` does not
apply: these packages are in no repository.

Then, separately and deliberately (it edits `config.xml`):

```sh
/usr/local/libexec/fips/fips-dns-setup
```

The daemon starts at boot from then on. To keep it installed but
dormant, set `fips_enable="NO"` in `/usr/local/etc/fips/fips.conf`;
`fips.sh onestart` still starts it by hand.

### "Allow IPv6" and the responder bind

`Allow IPv6` (System > Advanced > Networking) is **on in the factory
configuration**, so most installs need nothing here. The notes below are
for a firewall where it has been turned off.


**System > Advanced > Networking > Allow IPv6.** The mesh is IPv6
(`fd00::/8`) end to end. With that setting off, pfSense emits

```
block in  quick inet6 all
block out quick inet6 all
```

and a `quick` rule matches immediately — **no rule you add can override
it**. The mesh is dead in both directions.

The trap is that this does not look like a failure. The loopback IPv6
pass rule is unconditional, so the DNS responder keeps answering and
`.fips` names keep resolving; the outer UDP and TCP transports are IPv4
and keep peering happily. `fipsctl show status` looks healthy while
nothing crosses the mesh. **`.fips` resolving is not evidence that the
mesh carries traffic** — ping the address it returns.

Verify:

```sh
pfctl -sr | grep -c "Block all IPv6"      # must be 0
pfctl -sr | grep "let out anything IPv6"  # must be present
```

## .fips DNS integration

`fips-dns-setup` adds a marked block to **Services > DNS Resolver >
Custom options**, which is the only operator-writable surface in the
generated `unbound.conf`:

```
# BEGIN FIPS - managed by fips-dns-setup, do not edit this block
server:
    domain-insecure: "fips."
    do-not-query-localhost: no

forward-zone:
    name: "fips."
    forward-addr: 127.0.0.1@5354
    forward-first: no
# END FIPS
```

Each line earns its place:

- `domain-insecure` — the `.fips` zone is unsigned and pfSense validates
  DNSSEC by default, so without it every answer is discarded as bogus.
- `do-not-query-localhost: no` — unbound refuses loopback forwarders by
  default, which SERVFAILs every `.fips` query rather than asking the
  daemon. pfSense's `unbound.inc` never sets this. Note this applies to
  the **whole resolver**, not only the `fips.` zone: after this, unbound
  will also forward other loopback-directed queries it would otherwise
  refuse. On a firewall whose only loopback listener is the FIPS
  responder that changes nothing, but it is a resolver-wide setting.
- `forward-first: no` — never fall back to the public resolvers for a
  name the daemon declined. `.fips` does not exist outside the mesh, and
  leaking the query would publish which npubs this firewall talks to.

It is stored (base64-encoded) in `config.xml`, which is the point:
`config.xml` is pfSense's durable store — it survives reboots, config
restores, and removal of this package — so the `fips.` zone is not tied
to the package's own files. If the package is ever removed without
`fips-dns-teardown`, the zone keeps pointing at `127.0.0.1:5354` and
`.fips` fails loudly with SERVFAIL rather than resolving to something
else.

The block is written between markers and everything outside them is left
byte-for-byte alone, so your own custom options are safe. `write_config()`
records a config-history entry, so the edit is revertable from
**Diagnostics > Backup & Restore > Config History**.

To undo it while keeping the daemon:

```sh
/usr/local/libexec/fips/fips-dns-teardown
```

If this firewall uses the **DNS Forwarder (dnsmasq)** rather than the
DNS Resolver, the script says so; the equivalent single line under
Services > DNS Forwarder > Advanced Options is:

```
server=/fips/127.0.0.1#5354
```

## Firewall rules and the TUN interface

The daemon creates a `tun` interface for the mesh. Left unassigned, the
default pfSense ruleset gives it the posture most people want:

- `pass out ... all keep state` ("let out anything from firewall host
  itself") is not interface-scoped, so it covers `tun` — **outbound
  passes and creates state, replies return on that state**;
- the default deny covers inbound, so **unsolicited inbound is blocked**.

The sample `fips.yaml` binds its UDP and TCP transports to `0.0.0.0`,
i.e. every interface including WAN. Nothing is reachable from outside
only because pfSense's default WAN policy passes no unsolicited inbound;
if you add a WAN pass rule for another service, make sure it does not
cover the FIPS ports (2121/udp, 8443/tcp by default), or set
`transports.udp.bind_addr` / `transports.tcp.bind_addr` to the LAN
address. To accept inbound mesh connections deliberately, assign the
interface (Interfaces > Assignments) and add pass rules. Two caveats:

- **The interface name is kernel-assigned.** On FreeBSD the daemon reads
  back whatever the kernel gave it (`tun0`, `tun1`, ...); `tun.name` in
  `fips.yaml` is silently ignored on this platform. A pfSense assignment
  pins a name, so confirm it is stable across daemon restarts and
  reboots before building rules on it.
- **Match the daemon's posture to pf's.** pf dropping inbound does not
  stop the daemon advertising itself as reachable — peers keep dialing
  an endpoint that drops. If you are not allowing inbound, set
  `transports.udp.accept_connections: false` (refuses inbound `msg1` at
  the protocol level) or `outbound_only: true` (pure client) in
  `fips.yaml`.

LAN clients reaching the mesh through the firewall rely on state from
the LAN pass rule. That holds under the default *floating* state policy;
if System > Advanced > Firewall is set to interface-bound states, the
`tun` side needs its own pass rule.

## Upgrades and removal

A pfSense **firmware upgrade** does not remove this package.
`pfSense-upgrade` deletes and reinstalls only `pfSense-pkg-*` packages;
`fips` is a plain pkg and is left in place. This was confirmed on a live
**Plus 26.03.1 → 26.07** upgrade (aarch64): the package survived, the
daemon restarted at boot, and `.fips` still resolved. That is a *minor*
base change (FreeBSD 16 → 16). At a **major** change (CE 2.8.1 on
FreeBSD 15 → CE 2.9.0 on FreeBSD 16) a FreeBSD-15 binary runs on a
FreeBSD-16 kernel only through that kernel's compat layer — not tested —
so after a major upgrade rebuild and reinstall the package for the new
base (the `ce2.9-plus26-amd64` one)
rather than trusting compat indefinitely. (The minor-upgrade survival
above is from the hardware run; the cross-major compat behaviour is only
what `pfSense-upgrade`'s source implies — see "What is and is not
tested".)

A **package upgrade** (`pkg install ./<newer>.pkg`) stops the daemon
before replacing its binary and starts it again afterwards only if it
had been running. **`pkg delete`** stops it, takes the `.fips` block back
out of the DNS Resolver, and deletes the config files only if they are
still byte-identical to the shipped samples — an edited `fips.yaml`, and
the identity key it may hold, is left in place.

## Debugging

```sh
/usr/local/etc/rc.d/fips.sh status
tail -f /var/log/fips.log

drill -p 5354 <npub>.fips @127.0.0.1 AAAA   # the daemon directly
drill <npub>.fips AAAA                      # the full chain via unbound
ping6 <the AAAA it returned>                # proves the mesh, not just DNS

unbound-checkconf /var/unbound/unbound.conf
grep -A8 "Unbound custom options" /var/unbound/unbound.conf
pfctl -ss | grep tun                        # mesh state entries
```

`ifconfig <tun-name>` prints `Opened by PID <n>` for the process holding
a tun device. The interface is destroyed automatically when the daemon
exits.

## What is and is not tested

`testing/check-pfsense-pkg.sh` validates the package contents, the boot
script's behaviour and the config it ships, on any FreeBSD host. It runs
in CI. What it cannot cover — installing on pfSense, the `config.xml`
edit (which needs pfSense's PHP and `config.inc`), unbound answering
`.fips`, and pf passing mesh traffic — has no pfSense CI image to
automate against and remains a manual step.

Those manual steps have been exercised once, on pfSense Plus 26.03.1
aarch64: package install, boot script lifecycle, `fips-dns-setup`
writing the DNS Resolver block, `.fips` resolving through unbound, the
TUN interface coming up, and the mesh carrying traffic (304 packets
delivered, no loss, no drops). That is one run on one appliance, not a
gate — nothing re-checks it when this code changes.

Known still-unexercised paths, from that same run: `fips-dns-setup`'s
refusal path (it has only ever run against a responder that was already
answering), its DNS Forwarder branch, and `pkg delete`.
(`fips-dns-teardown` has since been run on the same box and restored
`custom_options` byte for byte.)

**No amd64 package has ever been installed.** The CE 2.8.1 (FreeBSD 15)
and the CE 2.9 / Plus 26.x (FreeBSD 16) amd64 packages are built and
pass the checker, and nothing more. The one hardware run was aarch64;
the amd64 packages share every script here and have had none of that
exposure, so read a passing check as "the package is well-formed", not
"it works".

That matters because the aarch64 run found several defects, every one in
this packaging rather than the daemon — a boot script whose pid check
never succeeded, a DNS setup that reported success while nothing was
listening, and a static build that faulted at `posix_spawn`. The daemon
itself needed no changes. An untested path in the amd64 packages is
exactly where the next one would sit.
