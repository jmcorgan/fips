# FIPS OpenWrt Package

This directory is an OpenWrt feed package that builds and installs FIPS on any
OpenWrt 22.03+ router via the standard `opkg` package system.

## Package contents

| Installed path | Purpose |
|---|---|
| `/usr/bin/fips` | Mesh daemon |
| `/usr/bin/fipsctl` | CLI control tool (`fipsctl show peers`, `fipsctl show links`, …) |
| `/usr/bin/fipstop` | Live TUI dashboard |
| `/usr/bin/fips-gateway` | Outbound LAN gateway service (not started by default) |
| `/usr/bin/fips-mesh-setup` | Opt-in helper — creates an open 802.11s mesh interface for router↔router backhaul |
| `/usr/bin/fips-ap-setup` | Opt-in helper — creates the open `!FIPS` access SSID for client devices |
| `/etc/init.d/fips` | procd service for the daemon (auto-start, crash respawn) |
| `/etc/init.d/fips-gateway` | procd service for the gateway (disabled by default) |
| `/etc/fips/fips.yaml` | Node configuration (edit before first start) |
| `/etc/sysctl.d/fips-bridge.conf` | Turns off `br_netfilter`'s firewall call hooks |
| `/etc/sysctl.d/fips-gateway.conf` | `proxy_ndp` and IPv6 forwarding for the gateway |
| `/usr/share/nftables.d/chain-post/{input,forward}_fips/10-fips-port-forwards.nft` | Lets fips-gateway's port forwards through the `fips` zone |
| `/usr/share/nftables.d/chain-pre/forward_wan/10-fips-wan-icmpv6.nft` | Refuses ICMPv6 from the `wan` zone into the mesh |
| `/etc/uci-defaults/90-fips-setup` | First-boot kernel modules, the `fips` firewall zone and dnsmasq `.fips` forwarding |
| `/lib/upgrade/keep.d/fips` | Preserves `/etc/fips/` across `sysupgrade` |

## Requirements

### Build host

| Requirement | Notes |
|---|---|
| OpenWrt SDK 22.03+ | Older versions lack fw4 / nftables support |
| Rust host toolchain | Enable in `make menuconfig` → Advanced → Rust, or install rustup |
| Rust target for your router | Added automatically by the Makefile via `rustup target add` |

### Router

| Requirement | Notes |
|---|---|
| `kmod-tun` | Required for `fips0` TUN interface |
| `kmod-br-netfilter` | Loaded, hooks off (`fips-bridge.conf`); see notes below |

Both kernel modules are listed as package dependencies (`DEPENDS`) and will be
installed automatically by `opkg`.

## Target architectures

The Makefile maps the OpenWrt `ARCH` variable to the correct Rust musl target:

| OpenWrt `ARCH` | Rust target |
|---|---|
| `aarch64` | `aarch64-unknown-linux-musl` |
| `x86_64` | `x86_64-unknown-linux-musl` |
| `mipsel` | `mipsel-unknown-linux-musl` |
| `mips` | `mips-unknown-linux-musl` |
| `arm` | `arm-unknown-linux-musleabihf` |

To add a missing architecture, add an `ifeq` block in `Makefile` mapping the
OpenWrt `ARCH` value to the Rust target triple.

## Building with the OpenWrt SDK

### 1. Obtain the SDK

Download the SDK for your router's target from
[downloads.openwrt.org](https://downloads.openwrt.org) and extract it.

### 2. Add this package

Copy or symlink this directory into the SDK's `package/` tree:

```bash
# From inside the SDK root:
ln -s /path/to/fips/packaging/openwrt-ipk package/fips
```

Or add the FIPS repository as a feed in `feeds.conf`:

```
src-git-full fips https://github.com/jmcorgan/fips.git
```

Then update and install feeds:

```bash
./scripts/feeds update fips
./scripts/feeds install -a -p fips
```

### 3. Build

```bash
make package/fips/compile V=s
```

The resulting `.ipk` is placed in `bin/packages/<arch>/`.

Installed on a router, the package enables and starts `fips` and leaves
`fips-gateway` disabled. Built into a firmware image, it is different: the
maintainer scripts do nothing at image build time, and the image build enables
every init script a package ships, `fips-gateway` included. To build an image
with the gateway off, pass `DISABLED_SERVICES="fips-gateway"` to the image
builder's `make image`.

### 4. Pin the source version

For reproducible production builds, replace `PKG_SOURCE_VERSION:=master` in
`Makefile` with a specific commit SHA and set `PKG_MIRROR_HASH` to the correct
hash (or keep `skip` for development):

```makefile
PKG_SOURCE_VERSION:=bf117dfabc123...  # full 40-char SHA
PKG_MIRROR_HASH:=skip
```

## Installing on the router

```bash
scp bin/packages/<arch>/fips_0.1.0-1_<arch>.ipk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 opkg install /tmp/fips_0.1.0-1_<arch>.ipk
```

## First-time configuration

Edit `/etc/fips/fips.yaml` on the router before starting the daemon:

```bash
ssh root@192.168.1.1
vi /etc/fips/fips.yaml
```

The default config enables:

- An ephemeral identity, generated on each start. Uncomment
  `node.identity.persistent: true` to keep one; the key is then saved next to
  the config, as `/etc/fips/fips.key`.
- TUN interface `fips0`
- DNS responder on `[::1]:5354`
- UDP transport on `[::]:2121`
- TCP transport on `0.0.0.0:8443`
- Ethernet transport, including the `wan`, `wwan` and `lan` entries

For Ethernet transport, edit the interface names in the `ethernet:` section to
match your router. **For the LAN, bind the LAN bridge (`br-lan`), never one of
its member ports** (on DSA boards `lan1`..`lanN`; on others whichever `ethN` the
bridge holds; `bridge link` lists them). A socket on a bridge member port sends
frames but never forms a link, because the bridge takes the frames that arrive
on its members; loading `br_netfilter` does not change that.
A lab test with a two-member Linux bridge found this with `br_netfilter`
unloaded, loaded with its call hooks off, and loaded with them on, while a
socket on `br-lan` worked both with `br_netfilter` unloaded and with it loaded
as shipped. Ports outside any bridge bind by their own name. The shipped
default WAN port is `eth0` (OpenWrt 24); on OpenWrt 25 (DSA) boards the WAN
port is named `wan`, and the `.apk` package ships that default. Run
`ip link show` to confirm the names on your board.

The lab used software bridges only. A DSA switch with hardware bridge offload
has not been checked, so confirm the LAN entry forms links on such a router.
`kmod-br-netfilter`, `fips-bridge.conf` and the module load in `90-fips-setup`
are kept until their removal has been checked on a router.

## Firewall

The package puts `fips0` in a firewall zone of its own, `fips`, created at
install:

```text
config zone 'fips'
        option name 'fips'
        list device 'fips0'
        option input 'REJECT'
        option output 'ACCEPT'
        option forward 'REJECT'
        option auto_helper '0'

config forwarding 'fips_lan'
        option src 'lan'
        option dest 'fips'

config rule 'fips_ping'
        option name 'Allow-FIPS-Ping'
        option src 'fips'
        option proto 'icmp'
        list icmp_type 'echo-request'
        option family 'ipv6'
        option target 'ACCEPT'
```

FIPS peers reach the router only with replies to its own connections, ping,
and fips-gateway's port forwards. The router reaches the mesh freely, and LAN
hosts reach it through the `lan` to `fips` forwarding. Router services such as
LuCI, SSH and DNS are not reachable from FIPS peers until you open them.

OpenWrt's stock `Allow-ICMPv6-Forward` rule accepts ICMPv6 from `wan` into
every zone, which would let a host on the WAN side ping mesh addresses and
send them ICMPv6 errors from the router. The package therefore installs a
second fw4 include, under `/usr/share/nftables.d/chain-pre/forward_wan/`, that
refuses ICMPv6 from `wan` into `fips0` ahead of that rule. ICMPv6 that belongs
to a tracked connection, such as an error for a LAN host's flow into the mesh,
is accepted before it. It applies to a zone named `wan`; a WAN zone under
another name needs a copy of the file under `chain-pre/forward_<zone>/`.

To open a port to FIPS peers, add a rule with `src fips`, for example SSH:

```bash
uci add firewall rule
uci set firewall.@rule[-1].name=FIPS-SSH
uci set firewall.@rule[-1].src=fips
uci set firewall.@rule[-1].proto=tcp
uci set firewall.@rule[-1].dest_port=22
uci set firewall.@rule[-1].target=ACCEPT
# optional: only this peer
uci set firewall.@rule[-1].src_ip=<peer mesh address>
uci commit firewall
/etc/init.d/firewall reload
```

Port forwards need no rule while fw4's `auto_includes` is on (the default):
the packaged include under `/usr/share/nftables.d/chain-post/` accepts them in
the zone's input and forward chains, after the zone's own rules. To restrict
them, add a `src fips` rule (with `dest lan` for a target on the LAN) that
matches the target's port, since filter rules see the packet after the
gateway rewrites its destination.

If fips-gateway serves a network whose `lan_interface` is in a zone other than
`lan`, add a forwarding from that zone, or its clients lose the mesh:

```bash
uci add firewall forwarding
uci set firewall.@forwarding[-1].src=<that zone>
uci set firewall.@forwarding[-1].dest=fips
uci commit firewall
/etc/init.d/firewall reload
```

A forwarding from any other zone does not give its hosts the mesh, because the
gateway serves only `lan_interface`.

If `fips0` is in a zone of your own instead of `fips`, the package leaves that
zone alone, and the packaged port-forward accept does not apply to it: it is
installed for the `fips` zone's chains only. Port forwards then need the same
`ct status dnat accept` for your zone: copy the packaged file into
`/usr/share/nftables.d/chain-post/input_<zone>/` and
`/usr/share/nftables.d/chain-post/forward_<zone>/` (and list both in
`/etc/sysupgrade.conf` to keep them across a sysupgrade), or move `fips0` into
the `fips` zone. The gateway's LAN path also needs a forwarding from the LAN
interface's zone into yours.

When `fips0` is in a zone whose input policy is ACCEPT, in `lan`, or in no zone
while the default input policy is ACCEPT (as on stock OpenWrt 22.03), an
install prints a line saying router services are reachable from FIPS peers.
An upgrade prints it only while there is no `fips` zone or the old include is
still present, so it does not report a `fips` zone whose input you opened
yourself, or `fips0` added back to `lan` beside the `fips` zone.

The zone holds the TUN by its name, `fips0`. If you rename the TUN with
`tun.name` in `/etc/fips/fips.yaml`, add the new name to the zone
(`uci add_list firewall.fips.device=<name>`, then commit and reload).
Otherwise the TUN is in no zone, which on a release whose default input policy
is ACCEPT leaves router services reachable from FIPS peers, and no line says
so.

To change the posture, edit the `fips` zone rather than deleting it; an
upgrade recreates a missing zone. On fw3 builds, which the package does not
support, the zone is created but port forwards are not let through.

Removing the package leaves the zone. To delete it:

```bash
uci delete firewall.fips
uci delete firewall.fips_lan
uci delete firewall.fips_ping
uci commit firewall
/etc/init.d/firewall reload
```

## Service management

```bash
/etc/init.d/fips start
/etc/init.d/fips stop
/etc/init.d/fips restart
/etc/init.d/fips enable    # start at boot (already enabled by opkg postinstall)
/etc/init.d/fips disable
```

### Outbound LAN gateway (optional)

The `fips-gateway` service is installed but disabled by default. It
turns the router into an outbound gateway that bridges LAN clients
onto the FIPS mesh. Enable only after configuring a `gateway:`
section in `/etc/fips/fips.yaml`:

```bash
/etc/init.d/fips-gateway enable
/etc/init.d/fips-gateway start
```

See `docs/tutorials/deploy-fips-gateway.md` in the source tree for
the full walkthrough.

## Inspection and logs

```bash
# Node-level status overview
fipsctl show status

# Peer table
fipsctl show peers

# Transport links
fipsctl show links

# Active end-to-end sessions
fipsctl show sessions

# Live TUI dashboard
fipstop

# Daemon logs (OpenWrt syslog)
logread | grep fips
```

See [`docs/reference/cli-fipsctl.md`](../../docs/reference/cli-fipsctl.md)
for the full subcommand list.

## Upgrading

OpenWrt 25 and later have no opkg. Upgrade there with the `.apk` package,
using the same command that installs it:

```bash
apk add --allow-untrusted /tmp/fips_<new-version>_<arch>.apk
```

The `.apk` package's upgrade scripts stop `fips` and `fips-gateway`, start
`fips` again, and start `fips-gateway` only if it was enabled; see
[`../openwrt-apk/README.md`](../openwrt-apk/README.md).

On OpenWrt 24.10 and earlier, install the new `.ipk` with a plain
`opkg install`:

```bash
opkg install /tmp/fips_<new-version>_<arch>.ipk
```

opkg runs this as an upgrade. The installed package's `prerm` stops `fips` and
`fips-gateway` without disabling them, and the new package's `postinst` starts
`fips` and starts `fips-gateway` again if it was enabled.

An upgrade from 0.5.1 or earlier is the exception. The `prerm` in those
packages disables `fips-gateway` and records nothing about whether it was
enabled, so the new `postinst` enables it again. If you had the gateway
disabled, disable it again after that first upgrade:

```bash
/etc/init.d/fips-gateway stop
/etc/init.d/fips-gateway disable
```

If opkg refuses because the new file's version sorts lower than the installed
one, as it can between development builds, add `--force-downgrade`. opkg then
takes the same upgrade path.

Do not use `--force-reinstall`. opkg runs it as a removal followed by a fresh
install, so `fips-gateway` ends up disabled. To turn it back on:

```bash
/etc/init.d/fips-gateway enable
/etc/init.d/fips-gateway start
```

The config in `/etc/fips/fips.yaml` and the identity key `/etc/fips/fips.key`
(when persistent identity is on) are preserved by `opkg` (the yaml is installed
as a conffile; the key is not a package file). Both survive `sysupgrade` via
`/lib/upgrade/keep.d/fips`.

### Upgrading from 0.5.2 or earlier: the firewall

Those packages put `fips0` in the `lan` zone and accepted all of its traffic
through `/etc/fips/firewall.sh`. The upgrade moves `fips0` into the `fips` zone
(see [Firewall](#firewall)), removes the old include, script and hotplug hook,
and reloads the firewall. Router services are then no longer reachable from
FIPS peers unless you open them. If you manage the router over FIPS, add the
SSH rule from the Firewall section before upgrading: fw4 skips a rule that
names a missing zone with a warning, and the rule takes effect at the
upgrade's reload.

If the reload fails, or the upgrade cannot tell whether it loaded, or the
firewall configuration cannot be saved, the upgrade prints a warning and blocks
new connections from FIPS peers until the firewall next reloads. The warning
names the remedy: `fw4 check` to see why a reload failed, or freeing overlay
space and then committing or rebooting when the configuration could not be
saved. In that last case the setup runs again at each boot until it can save.

On a full overlay, `uci commit` can report success after writing only part of
`/etc/config/firewall`, or none of it. The upgrade compares the saved file with
what it meant to save, and when they differ it warns that the file was left
damaged. The next firewall reload or reboot loads the damaged file, which can
cut off access from the LAN. The configuration the upgrade meant to save is in
`/tmp/fips-firewall.uci`, which a reboot clears, so free space on the overlay
and restore it first:

```bash
uci import firewall < /tmp/fips-firewall.uci
/etc/init.d/firewall reload
```

While the block is in place the old ruleset is still loaded, with `fips0` in
the `lan` zone. The block stops traffic from FIPS peers, but not traffic that
the old ruleset forwards into the mesh from other zones: ICMPv6, ESP and IKE
from `wan` through OpenWrt's stock rules (the wan include refuses the ICMPv6
only once the new ruleset loads), and whatever a forwarding or rule into `lan`
allows. That lasts until the firewall reloads cleanly.

Firewall changes staged with `uci` and not yet committed are committed by the
upgrade and loaded by its reload.

The upgrade does not cut connections FIPS peers opened to the router before
it: the firewall accepts traffic on a connection it already tracks, and a peer
can keep a UDP flow, such as one to DNS on port 53, open for as long as it
keeps sending. If router services were reachable from FIPS peers before the
upgrade, reboot the router afterwards to end those connections.

If `fips0` is in a zone of your own, the upgrade leaves it there but removes
the old include's accepts, so gateway port forwards and the gateway's LAN path
need the rules described in the Firewall section; the upgrade prints a line
saying so.

Installing an older package puts `fips0` back into `lan` until the next
install of a package with this zone.

A configuration backup taken before the upgrade carries the old firewall
setup, so take a new backup afterwards. After restoring an older one, redo the
migration by hand. Check the indexes first:

```bash
uci show firewall | grep -e "name='lan'" -e fips/firewall.sh
```

then, with those indexes:

```bash
uci del_list firewall.@zone[<lan index>].device=fips0
uci delete firewall.@include[<index of the fips include>]
rm -f /etc/fips/firewall.sh
uci set firewall.fips=zone
uci set firewall.fips.name=fips
uci add_list firewall.fips.device=fips0
uci set firewall.fips.input=REJECT
uci set firewall.fips.output=ACCEPT
uci set firewall.fips.forward=REJECT
uci set firewall.fips.auto_helper=0
uci set firewall.fips_lan=forwarding
uci set firewall.fips_lan.src=lan
uci set firewall.fips_lan.dest=fips
uci set firewall.fips_ping=rule
uci set firewall.fips_ping.name=Allow-FIPS-Ping
uci set firewall.fips_ping.src=fips
uci set firewall.fips_ping.proto=icmp
uci add_list firewall.fips_ping.icmp_type=echo-request
uci set firewall.fips_ping.family=ipv6
uci set firewall.fips_ping.target=ACCEPT
uci commit firewall
/etc/init.d/firewall reload
```
