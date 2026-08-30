# Getting Started with FIPS

FIPS (Free Internetworking Peering System) is a self-organizing
encrypted mesh network built on Nostr identities. Your machine
becomes a node in the mesh with a self-generated cryptographic
identity, and existing networking software — SSH, web servers,
file transfer, anything IPv6-native — runs over the mesh
unchanged.

There are two common ways to deploy FIPS, and the rest of this
guide and the linked docs branch accordingly:

- **As an overlay** on top of existing IP networks (Ethernet,
  WiFi, the public internet, Tor), FIPS lets your node reach
  any other peer regardless of NAT, ISP, or physical location.
- **From the ground up** over non-IP transports — raw Ethernet,
  WiFi, Bluetooth — FIPS provides a complete permissionless
  network without any pre-existing IP infrastructure, ISP, or
  DNS.

The two paths share a lot of common ground — install, identity,
configuration. They diverge mainly in transport setup and the
deployment topology you choose.

There is no central server. Any node can run; any pair of
running nodes can mesh.

## What you'll need

- A Linux, macOS, FreeBSD, or Windows host. Linux is the most
  exercised platform; macOS, FreeBSD, and Windows installers are
  available. The FreeBSD package is built for **x86_64 only**.
- The pre-built installer for your platform (see the project
  README's [Quick start](../README.md#quick-start) section for
  download links), **or** a source checkout if you want to build
  the installer yourself.
- For the source-build path only: a working Rust toolchain (the
  version pinned in `rust-toolchain.toml` is auto-installed by
  rustup), and the platform-specific build dependencies listed in
  [packaging/README.md](../packaging/README.md).

## Install

FIPS is installed by running a binary installer for your
platform. The installer drops the daemon and CLI tools into
system locations, installs systemd / launchd / rc.d /
Windows-service unit files, places a default `fips.yaml`, and
creates the `fips` system group. There is no `cargo install`
path: the daemon needs more than just binaries copied into place.

You can either build the installer yourself from source, or
download a pre-built one from the release distribution. Both
paths produce the same installer artifacts and the same
post-install state.

### From the release distribution

The most direct path. The release distribution carries a
per-platform installer:

- Debian/Ubuntu: `.deb` package
- Arch Linux: `fips` AUR package
- OpenWrt: `.ipk` and `.apk` packages
- macOS: `.pkg` installer
- FreeBSD: native `.pkg` (x86_64 only)
- Windows: `.zip` with service-install scripts
- Generic systemd Linux: `.tar.gz` with an `install.sh` script

See the [project README's Quick start section](../README.md#quick-start)
for download links and per-platform invocations.

### FreeBSD

FreeBSD gets a native package built from `packaging/freebsd/`. It
ships `fips`, `fipsctl`, `fipstop`, the `fips` and `fips_dns` rc.d
services, and `.fips` DNS integration. `fips-gateway` is **not**
included: its NAT backend is nftables, which is Linux-only. The
Ethernet and BLE transports are unavailable on FreeBSD; UDP, TCP,
Tor, and Nym are.

**One architecture.** The published artifact is
`fips-<version>-freebsd-amd64.pkg`. There is no aarch64 FreeBSD
build, so on any other architecture use the from-source path below.

```sh
pkg add ./fips-<version>-freebsd-amd64.pkg
cp /usr/local/etc/fips/fips.yaml.sample /usr/local/etc/fips/fips.yaml
sysrc fips_enable=YES fips_dns_enable=YES
service fips start
service fips_dns start
fipsctl show status
```

FreeBSD differs from the Linux layout in three places worth knowing
before you go looking for files:

- Config lives at `/usr/local/etc/fips/fips.yaml`, not `/etc/fips/`.
  It installs with sample semantics and mode `0600`, so an edited
  file survives `pkg upgrade` and `pkg delete`, and a `nsec:` in it
  is not world-readable.
- The daemon runs under `daemon(8)` with pidfile
  `/var/run/fips/fips.pid` and logs to `/var/log/fips.log`. The
  rc.conf knobs are `fips_config`, `fips_flags`, and
  `fips_logfile`.
- The control socket resolves to `/var/run/fips/control.sock`. As on
  Linux, a `fips` group is created and its members can run `fipsctl`
  and `fipstop` without root (`pw groupmod fips -m <user>`, then
  re-login).

Making the local resolver the *system* resolver is a one-time
operator step the package deliberately does not take, and there are
field-tested caveats around unbound upstreams and `/etc/resolv.conf`.
Both are covered in the FreeBSD section of
[packaging/README.md](../packaging/README.md) and in
`packaging/freebsd/README.md`.

### From source

For development, custom builds, or unsupported architectures.
The `packaging/` tree builds the same installer formats locally;
you then apply the resulting installer the same way you would a
downloaded one.

```sh
git clone https://github.com/jmcorgan/fips.git
cd fips/packaging
make deb         # or: tarball, ipk, apk, aur, pkg, freebsd, zip, all
```

The resulting installer lands in `deploy/` at the project root.
Apply it the same way you would a downloaded one (for example
`sudo dpkg -i deploy/fips_*.deb` on Debian/Ubuntu).

See [packaging/README.md](../packaging/README.md) for per-format
build details, cross-target options, and the full `make` target
list.

### With Nix (flake)

On Nix/NixOS, a [flake](../flake.nix) at the project root builds the
binaries from source with the pinned toolchain and no manual
prerequisite install:

```sh
nix build .#fips          # all four binaries, into ./result/bin
nix develop               # dev shell with the toolchain + build deps
```

This path produces binaries only — it does not run the installer, so
there are no systemd units, no `fips` group, and no default `fips.yaml`.
On NixOS, wire the daemon in through your system configuration using the
flake's `nixosModules.default` output instead: import it and set
`services.fips.enable = true`. See
[packaging/nixos/README.md](../packaging/nixos/README.md) and the Nix /
NixOS section of [packaging/README.md](../packaging/README.md).

## What's installed and running

Here's what the installer leaves on your machine, what's
running, and what you'll need to set up yourself.

**Binaries installed system-wide:**

- `fips` (daemon)
- `fipsctl` (control-socket client)
- `fipstop` (live-status TUI)
- `fips-gateway` (Linux only)

**Files placed on disk:**

- `/etc/fips/fips.yaml` — default daemon config (preserved on
  upgrade). On macOS and FreeBSD this is
  `/usr/local/etc/fips/fips.yaml`.
- `/etc/fips/fips.nft` — mesh-interface nftables baseline (used
  only when the firewall service is enabled). Linux only.
- `/etc/fips/fips.d/` — empty drop-in directory for operator
  nftables additions. Linux only.
- Systemd, launchd, rc.d, or Windows-service unit files for the
  fips services. FreeBSD installs `fips` and `fips_dns` only, since
  `fips-gateway` and the nftables firewall service are Linux-only.

**System changes:**

- A `fips` system group is created. Add your user to it
  (`sudo usermod -aG fips $USER`, then re-login) to run
  `fipsctl` and `fipstop` without `sudo`.
- The runtime directory `/run/fips/` exists with mode
  `0750 root:fips`.

**Services enabled at install, and started on the next boot:**

- `fips.service` — the daemon. Brings up the `fips0` TUN
  adapter, listens on the configured transports, and exposes
  the control socket at `/run/fips/control.sock`.
- `fips-dns.service` — wires `.fips` hostname resolution into
  the host resolver (a `/etc/systemd/resolved.conf.d/` drop-in
  pointing at `[::1]:5354` on systemd hosts).

The Debian package enables both and starts neither, so a fresh install
leaves them stopped. Start them yourself rather than waiting for a
reboot:

```bash
sudo systemctl start fips fips-dns
```

**Services installed but not enabled** (operator opt-in):

- `fips-firewall.service` — applies `/etc/fips/fips.nft` to
  the mesh interface. See
  [how-to/enable-mesh-firewall.md](how-to/enable-mesh-firewall.md).

**What's working once both services are running:**

- The daemon is running with a fresh **ephemeral** identity —
  a new Nostr keypair is generated on every start.
- The `fips0` TUN adapter exists with the daemon's mesh address.
- The daemon's transport listeners are up: UDP `0.0.0.0:2121`
  and TCP `0.0.0.0:8443`. They are inert at this point because
  no other node knows your daemon's npub yet — see "What's not
  yet configured" below.
- `.fips` hostname resolution is plumbed into the host
  resolver.

**What's not yet configured** — these are what guide your next
steps:

- **No peers.** The daemon has nobody to talk to until you add
  a static peer entry, enable Nostr-mediated discovery, or
  bring up a transport (Ethernet, Bluetooth) where peers find
  each other automatically on the same physical link.
- **Ephemeral identity.** Your node's npub changes every
  restart. The
  [persistent-identity tutorial](tutorials/persistent-identity.md)
  walks through pinning the daemon to a stable Nostr keypair
  for any node others will reference by name.
- **Mesh firewall not active.** Inbound exposure on `fips0`
  follows the host's existing firewall rules until you enable
  the baseline service.

## Reaching mesh nodes by name

A FIPS node is identified by its Nostr public key (`npub1...`).
For ordinary IP software running over the mesh — SSH, web
browsers, `ping`, file transfer — use the form `<npub>.fips`
as the destination; the local `.fips` resolver translates that
to the corresponding mesh IPv6 address so the FIPS node can be
found. The resolver runs entirely on your machine and does not
generate any external DNS traffic.

For shorter forms, the resolver also consults two host maps
before falling back to direct npub lookup: `/etc/fips/hosts`
(shipped pre-populated with the public test mesh roster, and
freely editable for your own entries) and the `alias:` field
on configured peers in `fips.yaml`. So `test-us01.fips`,
`my-laptop.fips`, or any other shortname you map resolves the
same way `<npub>.fips` does. See
[how-to/host-aliases.md](how-to/host-aliases.md) for the full
mechanics.

## Join the test mesh

The fastest way to see FIPS in action is to connect your daemon
to the public FIPS test mesh. The
[Join the Test Mesh](tutorials/join-the-test-mesh.md) tutorial
walks through adding a single static peer entry, watching the
link come up, and reaching both that peer and a second mesh node
forwarded through it — a ten-minute exercise that demonstrates
the central FIPS guarantee that one good peer connects you to
the rest of the mesh.

## Where to go next

Documentation is organised into four sections, each with a different
job. Pick the one that matches what you want to do.

### [Tutorials](tutorials/)

Step-by-step lessons that take you from zero to a working setup.
Read these end-to-end. Start with
[Join the Test Mesh](tutorials/join-the-test-mesh.md) and follow
with
[ipv6-adapter-walkthrough](tutorials/ipv6-adapter-walkthrough.md)
to understand what each piece does, then move on to
[persistent-identity](tutorials/persistent-identity.md) and
the three Nostr-discovery tutorials —
[resolve-peers-via-nostr](tutorials/resolve-peers-via-nostr.md),
[advertise-your-node](tutorials/advertise-your-node.md), and
[open-discovery](tutorials/open-discovery.md) — to give your
node a stable npub, look up peer endpoints, publish your
own, and join the ambient discovery namespace. Then [host-a-service](tutorials/host-a-service.md) for hosting
a service on your node, and [ground-up-mesh](tutorials/ground-up-mesh.md)
for the second deployment mode where two devices peer over
Ethernet, WiFi, or Bluetooth with no IP between them.

### [How-To Guides](how-to/)

Task-oriented recipes for operators with a specific goal: enable a
firewall, deploy the LAN gateway, set up Bluetooth peering,
diagnose an MTU problem, configure persistent identity. Each guide
takes the shortest correct path from "I want to do X" to "X is done".

### [Reference](reference/)

Lookup material consulted on demand: wire formats, configuration
keys, command-line flags, control-socket commands. Austere by
design; no guidance on when to use a feature.

### [Design](design/)

Architectural and protocol-level explanations: the mesh layer, the
session layer, the spanning tree, Bloom-filter discovery, the
unified MTU model, the IPv6 adapter. Read these to understand *why*
FIPS makes the choices it does.

The design section's
[fips-concepts.md](design/fips-concepts.md) is a good entry point if
you want the mental model before touching any commands.
