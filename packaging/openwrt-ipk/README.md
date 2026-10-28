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
| `/usr/bin/fips-mesh-setup` | Opt-in helper — creates an open 802.11s mesh interface for router↔router backhaul, in the `fips_mesh` firewall zone, with basic rates 6, 12 and 24 Mb/s |
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

### The 802.11s mesh zone

`fips-mesh-setup` puts each mesh interface it creates in a firewall zone of its
own, `fips_mesh`, before it brings the radio up:

```text
config zone 'fips_mesh'
        option name 'fips_mesh'
        option input 'REJECT'
        option output 'ACCEPT'
        option forward 'REJECT'
        option auto_helper '0'
        list device 'fips-mesh0'
```

The mesh is open at the radio layer, so anyone in radio range can join it. An
interface in no zone meets the default input policy, which on stock OpenWrt
22.03 is ACCEPT, and would let them reach router services such as LuCI, SSH
and DNS at the interface's link-local address. The zone rejects all IP input
and forwarding on the mesh, including FIPS UDP (port 2121) and mDNS, so FIPS
peers over the mesh use the Ethernet transport, which is not IP and does not
pass the firewall.

The zone holds each interface by its name. If you put a mesh interface in a
zone of your own before running `fips-mesh-setup`, it is left there, and the
helper prints a warning that names the zone, saying router services are
reachable over the mesh when that zone's input policy is ACCEPT. The zone is
created once and is yours from then on: the helper adds and removes
interfaces but does not rewrite its options, and warns when its input policy
is ACCEPT or the zone is disabled. If you rename a mesh interface by hand, add
the new name to the zone (`uci add_list firewall.fips_mesh.device=<name>`, then
commit and reload).

`fips-mesh-setup remove` takes each interface out of the zone, and deletes the
zone with the last one. An upgrade adds mesh interfaces made by older packages,
which put them in no zone, to the zone. A reinstall of the same version with a
plain `opkg install` does not run the package's setup, so run the helper's
`zone` subcommand yourself:

```bash
fips-mesh-setup zone
```

As with the `fips` zone, the helper and the upgrade check the loaded ruleset
after the firewall reload. If the reload failed, IP traffic arriving on the mesh
interfaces is dropped until the firewall reloads cleanly, and a warning says
so. If the firewall configuration cannot be saved, `fips-mesh-setup` does not
create the mesh, and an upgrade drops IP traffic arriving on the mesh
interfaces until the firewall next reloads (`fips-mesh-setup close` does the
same by hand). When the save left the file damaged, the warning names the
copy to restore before any reload or reboot:

```bash
uci import firewall < /tmp/fips-mesh-firewall.uci
/etc/init.d/firewall reload
```

Removing the package leaves the zone, because the mesh interfaces stay
configured. Once you have removed the mesh, delete the zone with:

```bash
uci delete firewall.fips_mesh
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

The first start gives the LAN the address `2001:2:f1b5::1/64`
(`network.lan.ip6addr`), because Android and Chrome send no AAAA
queries on a LAN that has only ULA addresses. An IPv6 address you set
there yourself is left in place and the gateway's address is not added
beside it, so on a LAN whose only address you set is a ULA those
clients still send no AAAA queries. The address lies in an unassigned
part of IANA's `2001::/23` block and is not routed on the internet. It
stays across stops and restarts while the service is enabled, because
changing it reloads the network, which on OpenWrt 25.12 recreates
`br-lan` and drops the LAN for a few seconds. Turning the gateway off
deletes it: `disable` of a stopped gateway, `stop` of a disabled one
(so `stop` and `disable` in either order), a start with
`gateway.enabled` not true in `fips.yaml`, and removing the package.
Disabling a running gateway and then rebooting deletes nothing:
`disable` keeps the address while the gateway runs, and a disabled
service is neither stopped at shutdown nor started at boot. Run
`/etc/init.d/fips-gateway stop` once afterwards; it deletes the
address and withdraws the gateway's RA settings.

While it runs, the gateway sets the LAN's `ra_default` to 2, so that
odhcpd advertises a default route even without upstream IPv6, and
advertises a route to its address pool. It keeps the `ra_default` it
replaced in `/etc/fips/gateway-ra-default.saved`, and a stop puts that
value back, also after a power loss while the gateway ran. A stop with
nothing saved, such as the one every package upgrade and removal makes
whether or not the gateway ran, leaves `ra_default` alone unless it is
2, the value an older package's start left.

The LAN is the device `gateway.lan_interface` names, `br-lan` by
default, which may be a VLAN device such as `br-lan.3`. The pool
route, its advertisement, the address and `ra_default` go to the
network interface whose `device` is that name, or to `lan` when no
interface has it. Read `network.lan` in this section as that
interface.

On a router with upstream IPv6, while the address is present, LAN
clients may use it as the source for connections to any destination
that shares more leading bits with it than with the client's upstream
address, and those connections then fail or fall back slowly. With an
upstream address in `2a00::/7`, that is every destination in
`2000::/5`.

A sysupgrade that keeps settings but drops the package runs none of
the steps above. Delete the address by hand:

```bash
uci delete network.lan.ip6addr
uci commit network
/etc/init.d/network reload
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

On a router with no internet access, add `--no-network --repositories-file
/dev/null` so apk does not try the package feeds.

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

### Upgrading from 0.5.2 or earlier: the 802.11s mesh's basic rates

802.11s mesh points peer only when they join with the same basic rates. The
`fips-mesh-setup` in those packages set none, and OpenWrt releases then differ:
24.10 joins through `iw` with the radio's basic rates, by default 6, 12 and
24 Mb/s on 2.4 GHz, while 25.12 joins with the kernel's, 1, 2, 5.5 and 11 Mb/s
on 2.4 GHz. A 24.10 router and a 25.12 router each hear the other's beacons and
never peer. `fips-mesh-setup` now sets `basic_rate '6000 12000 24000'` on every
mesh interface it creates, which 24.10 and 25.12 both honour. On those releases
a `basic_rate` on the interface overrides one set on the radio, so a rate
choice you made on the radio (`basic_rate`, `legacy_rates` or `cell_density`)
no longer applies to the mesh; set it on the mesh interface instead.

The upgrade sets that value on each mesh interface `fips-mesh-setup` made that
has no `basic_rate`, and prints a line naming them. It leaves wireless
interfaces the helper did not make alone, and keeps a `basic_rate` you set on a
fips mesh interface yourself, printing a line that names it. Running
`fips-mesh-setup <radio>` again also keeps one. The upgrade saves the wireless
configuration and does not run `wifi reload` itself, but the rates apply at the
next reboot or network reload of any kind: `wifi reload`,
`/etc/init.d/network reload`, a LuCI apply, or the fips gateway starting or
being turned off. On a router with the gateway enabled, an upgrade from 0.5.2
or earlier starts the gateway, which reloads the network to set the LAN
prefix, so the rates apply during the upgrade itself.

From then on the router peers only with mesh points that join with the same
rates. A router still on the old package, or upgraded but not yet reloaded,
stops peering with it if it joins with other rates: on 2.4 GHz that is a 25.12
router, or any 22.03 or 23.05 router (see below), while a 24.10 router on
default settings already uses these rates. On 5 GHz both releases are expected
to use these rates already; that has not been checked on a router.

When you reach routers over the mesh, upgrade them one at a time, farthest
first, and run `wifi reload` on each right after its upgrade. The reload can
recreate the mesh interface; a running `fips` rebinds to the recreated
interface and forms its links again without a restart. Over SSH, run the
upgrade and the reload as one detached command, since the session can drop
part-way; with the `.apk`, put the `apk add` command above in place of
`opkg install`:

```bash
sh -c 'trap "" HUP
  opkg install /tmp/fips_<new-version>_<arch>.ipk
  wifi reload' \
  </dev/null >/tmp/fips-upgrade.log 2>&1 &
```

The command ignores the hangup itself because OpenWrt's BusyBox does not
always include `nohup` or `setsid`. A router that loses its peerings then is
at the edge of what you reach, and the routers you reach it through keep
theirs until their own turn; the link to it comes back once the router you
reach it through has been upgraded and reloaded. Upgrading a near router first
can cut off every router reached through it, which then needs another path,
such as its LAN, to finish the upgrade.

OpenWrt 22.03 and 23.05 pass no basic rates to a mesh join, whatever is set on
the interface or the radio, so on 2.4 GHz they join with 1, 2, 5.5 and 11 Mb/s.
Upgrading the package does not change that, and such a router stops peering
with 24.10 and later routers once those are upgraded and reloaded. To keep a
22.03 or 23.05 router in a 2.4 GHz mesh, set the rates it uses on the 2.4 GHz
mesh interface of every 24.10 or later router in that mesh (here the one on
`radio1`); the upgrade keeps them:

```bash
uci set wireless.fips_mesh_radio1.basic_rate='1000 2000 5500 11000'
uci commit wireless
wifi reload
```

A reinstall of the same version with a plain `opkg install` does not run the
package's setup, so run the helper's `rates` subcommand yourself:

```bash
fips-mesh-setup rates
wifi reload
```

If the wireless configuration cannot be saved, the upgrade says so, and its
setup runs again at each boot until it can save. When the upgrade could not
save the firewall configuration, which can mean the overlay is full, it leaves
the wireless configuration alone and sets the rates at a later boot. When the
save left `/etc/config/wireless` damaged, the warning says so; free space on the
overlay and restore it before the router reboots:

```bash
uci import wireless < /tmp/fips-mesh-wireless.uci
```
