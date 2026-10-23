# Set Up an 802.11s Mesh Backhaul (OpenWrt)

Link FIPS routers over radio — no cables, no APs, no shared
infrastructure — by running the Ethernet transport on an open 802.11s
mesh interface. The radio layer provides nothing but L2 frames to
direct neighbors; FIPS provides everything else: encryption and
authentication (the Noise handshake), peer discovery (Ethernet beacons), and
routing (the spanning tree).

For the transport design, see
[../design/fips-transport-layer.md](../design/fips-transport-layer.md).
For all `transports.ethernet.*` configuration keys, see
[../reference/configuration.md](../reference/configuration.md).

## Why open, why forwarding off, why fixed basic rates

Three deliberate choices distinguish this from a stock 802.11s setup:

- **`encryption none`** — the mesh is open on purpose. Every FIPS peer
  link is already authenticated and encrypted by the Noise
  handshake, so SAE at L2 would duplicate that work, add a shared
  credential to provision across routers, and (on ath10k) force the
  firmware into its slower raw Tx/Rx mode. A stranger can form an
  802.11s peering with your router *and* a FIPS peer link on top of it —
  the same open model as mDNS and BLE discovery, where the advert is
  only a hint and the handshake authenticates each link (no
  impersonation, no MITM) rather than gating who may peer. Admission is
  open up to the daemon's max-peers cap. What you concede: any nearby
  radio can peer and reach the FIPS overlay surface; L2 metadata (MAC
  addresses, frame sizes) is visible in the air; a hostile radio can
  burn airtime — all inherent to an open radio link. Router services
  (LuCI, SSH, DNS) and the daemon's UDP and mDNS ports are not reachable
  over the mesh: the helper puts the mesh interface in the `fips_mesh`
  firewall zone, which rejects all IP input and forwarding.
- **`mesh_fwding 0`** — disables 802.11s's own HWMP routing so each
  mesh link is a plain neighbor link. FIPS is the routing layer; two
  routing layers would fight, and broadcast discovery beacons would
  flood the whole mesh instead of reaching direct neighbors only.
- **`basic_rate '6000 12000 24000'`**: mesh points peer only when
  they join with the same basic rates, and OpenWrt releases pick
  different ones when none is set. On 2.4 GHz, 24.10 joins through
  `iw` with the radio's (by default 6, 12 and 24 Mb/s) and 25.12 with
  the kernel's (1, 2, 5.5 and 11 Mb/s), so a 24.10 router and a 25.12
  router hear each other's beacons and never peer. The helper sets 6,
  12 and 24 Mb/s, which 24.10 and later honour and which costs less
  airtime than the 802.11b rates. A `basic_rate` you set yourself on
  a mesh interface is kept, and overrides one set on the radio.
  OpenWrt 22.03 and 23.05 pass no basic rates to a mesh join, so on
  2.4 GHz they join with 1, 2, 5.5 and 11 Mb/s whatever is set, and
  do not peer with routers on these rates. To keep such a router in a
  2.4 GHz mesh, set `basic_rate '1000 2000 5500 11000'` on the mesh
  interface of every 24.10 or later router in it.

The interface is **not** bridged into `br-lan` — the FIPS Ethernet
transport binds it directly.

## When to use

- Two or more OpenWrt FIPS routers within radio range of each other,
  where running cable is impractical.
- You want the mesh segment to keep working with zero shared
  credentials or per-site configuration ("flash and drop in").

It is **not** for connecting phones or laptops — client devices
cannot join an 802.11s mesh. They enter the mesh through a normal AP
on the same router (see constraints below), or over BLE.

## Requirements

- OpenWrt 22.03+ with the FIPS package installed.
- A radio whose driver supports mesh point interfaces. Check with:

  ```sh
  iw list | grep -A 10 "Supported interface modes" | grep "mesh point"
  ```

  The mainstream OpenWrt chips (ath9k, ath10k, mt76) all qualify.
- Ideally a dual- or tri-band router, so one band can be dedicated to
  the backhaul (see constraints).

## Step 1 — create the mesh interface(s)

On **each** router, run the helper once per radio you want in the
backhaul:

```sh
fips-mesh-setup radio1
```

This creates an open 802.11s interface with mesh ID `fips-mesh`,
HWMP forwarding off and basic rates 6, 12 and 24 Mb/s, attaches it to
an unmanaged netifd interface (no IP configuration — none is needed),
puts it in the `fips_mesh` firewall
zone, which rejects all IP input and forwarding (the Ethernet transport
is not IP and is not affected), and reloads the firewall and then the
radio. It does not touch `/etc/fips/fips.yaml`: the matching `meshN`
transport ships enabled and the daemon binds the interface once it
exists (see Step 2). Interfaces are named by radio index: `radio0` → `fips-mesh0`,
`radio1` → `fips-mesh1`. Pass a second argument to use a different
mesh ID.

Note: the helper runs `wifi reload`, which re-applies the whole
wireless config and so briefly drops every client AP on all radios for
a few seconds. `fips-mesh-setup remove` reloads the same way. Expect
the blip if clients are connected.

On dual-band routers, meshing **both** bands is worth it: 2.4 GHz
reaches further at lower rates, 5 GHz carries more over shorter
links. Note this is **failover, not multipath**: FIPS keeps one
active link per peer, so traffic uses one band at a time — the other
is a standby that re-establishes the peer if the active link dies
(detection via keepalive timeout, so a cutover takes seconds, not
milliseconds):

```sh
fips-mesh-setup radio0
fips-mesh-setup radio1
```

**Pin the same channel on every backhaul router, per band.** Mesh
points only peer on the same channel, and the mesh inherits whatever
the radio is set to — with `channel 'auto'` (the default on many
devices) each router picks its own and the mesh silently never forms.
The script prints the radio's current band and channel and warns on
`auto`:

```sh
uci set wireless.radio1.channel='36'
uci commit wireless && wifi reload
```

Prefer a non-DFS channel (36–48 on 5 GHz): on DFS channels the radio
must wait ~60 s in CAC before transmitting after every reload.

Equivalent manual UCI (per radio), if you prefer to see what it does:

```sh
uci batch <<'EOF'
set wireless.fips_mesh_radio1=wifi-iface
set wireless.fips_mesh_radio1.device='radio1'
set wireless.fips_mesh_radio1.mode='mesh'
set wireless.fips_mesh_radio1.mesh_id='fips-mesh'
set wireless.fips_mesh_radio1.encryption='none'
set wireless.fips_mesh_radio1.mesh_fwding='0'
set wireless.fips_mesh_radio1.basic_rate='6000 12000 24000'
set wireless.fips_mesh_radio1.ifname='fips-mesh1'
set wireless.fips_mesh_radio1.network='fips_mesh_radio1'
set network.fips_mesh_radio1=interface
set network.fips_mesh_radio1.proto='none'
set firewall.fips_mesh=zone
set firewall.fips_mesh.name='fips_mesh'
set firewall.fips_mesh.input='REJECT'
set firewall.fips_mesh.output='ACCEPT'
set firewall.fips_mesh.forward='REJECT'
set firewall.fips_mesh.auto_helper='0'
add_list firewall.fips_mesh.device='fips-mesh1'
EOF
uci commit
/etc/init.d/firewall reload
wifi reload
```

## Step 2 — check the FIPS transport binding

The `fips.yaml` shipped in the OpenWrt package carries one transport
entry per radio, **enabled** and marked `optional: true`. The daemon
treats a named interface that is not there as absent rather than as a
failure, and `optional: true` is what keeps a stock install that never
runs this helper quiet and un-`Degraded` about a radio it was never
going to have. There is normally nothing to do here. If you maintain
your own config (or ran the manual UCI above instead of the helper),
make sure the entries are present:

```yaml
transports:
  ethernet:
    mesh0:
      interface: "fips-mesh0"
      optional: true
      listen: true
      announce: true
      auto_connect: true
      accept_connections: true
    mesh1:
      interface: "fips-mesh1"
      listen: true
      announce: true
      auto_connect: true
      accept_connections: true
```

`listen:` was called `discovery:` before v0.5.0; the old spelling still
parses as an alias, so an existing config keeps working (see
[../reference/configuration.md](../reference/configuration.md)).

## Step 3 — no restart needed

The daemon binds an interface when it appears. A transport whose
interface is missing is *absent*, not skipped: it waits, binds within
a second of the interface coming up, unbinds if it goes away, and
rebinds when it returns. Order does not matter, and neither
`/etc/init.d/fips restart` nor any hotplug rule is part of this
procedure.

Watch it happen:

```sh
fipsctl show transports
```

The transport's `interface` block reports `presence` (`absent` /
`binding` / `present`), `policy` (`required` / `optional`) and how
long it has held that state.

If you *changed a config value* above rather than only creating an
interface, that does need a restart — configuration is read at
startup, interfaces are not:

```sh
/etc/init.d/fips restart
```

## Verify

L2 first — the 802.11s peering, with a second configured router in
range:

```sh
iw dev fips-mesh0 station dump
```

You should see one station entry per neighbor router, with signal
levels. No entries means a radio problem, not a FIPS problem — triage
in this order:

1. **Channel mismatch** (the most common cause): compare
   `iw dev fips-mesh0 info` on both routers — mesh ID *and* channel
   must match exactly.
2. **The mesh interface never joined** — `iw dev fips-meshX info`
   shows `type mesh point` but **no channel line**, and `station dump`
   is empty. Usual cause: a client (`sta`) interface on the same
   radio. A STA must follow its upstream AP's channel, the whole
   radio follows the STA, and a mesh pinned to a different channel
   silently stays down. Check for a STA sharing the radio
   (`iw dev`, look for `type managed` on the same phy), compare
   `iw dev <sta-iface> info | grep channel`, and re-pin the mesh
   channel to match — on every backhaul router.
3. **Is the other router transmitting at all?**

   ```sh
   iw dev fips-mesh0 scan | grep -i -B4 "MESH ID"
   ```

   Its mesh ID visible → transmission works, peering is failing
   (mesh ID typo, one side has encryption set, or the basic rates
   differ; see the next item). Nothing visible →
   check `wifi status` on the other router, remember the ~60 s DFS
   CAC wait, and confirm the country code is set
   (`uci get wireless.radio1.country`) — an unset regdomain can
   block channels entirely.
4. **Basic rates differ**: beacons are heard both ways and the
   station dump stays empty. Compare
   `uci get wireless.fips_mesh_radio1.basic_rate` on both routers. A
   mesh interface made by a fips package up to 0.5.2 has none, and on
   OpenWrt 25.12 joins with 1, 2, 5.5 and 11 Mb/s, which no router on
   `6000 12000 24000` peers with. Upgrading the package sets the rates
   on such an interface; `fips-mesh-setup rates` does the same by hand.
   Either way they apply at the next reboot or network reload of any
   kind (`wifi reload`, a LuCI apply, or the fips gateway starting,
   which an upgrade does when the gateway is enabled). Until every
   router in the mesh is upgraded and reloaded, one left on the old
   rates stops peering with the upgraded ones, so upgrade routers you
   reach over the mesh one at a time, farthest first. A router on OpenWrt 22.03 or
   23.05 joins a 2.4 GHz mesh with 1, 2, 5.5 and 11 Mb/s whatever its
   `basic_rate`; see the basic rates item at the top of this guide.
5. `logread | grep -iE "mesh|fips-mesh0"` on both sides.

Then the FIPS layer on top:

```sh
logread | grep -i beacon        # beacons flowing on the new transport
fipsctl show peers              # neighbor authenticated and connected
fipsctl show links              # link on the 'ethernet' transport
```

Discovery is automatic: each node beacons its pubkey every few
seconds, and `auto_connect` initiates the Noise handshake on first
sight.

## Constraints

- **Airtime is shared per radio.** All virtual interfaces on one
  radio (AP + mesh) share one channel, and multi-hop forwarding on a
  single radio roughly halves throughput per hop. On dual/tri-band
  hardware, dedicate one band to `fips-mesh0` and serve clients on
  the others.
- **AP + mesh coexistence is driver-dependent.** It works on the
  mainstream chips (this is the standard Freifunk/Gluon setup), but
  check `iw list` under "valid interface combinations" for your
  hardware.
- **Clients can't join.** Phones and laptops reach the mesh through
  the router's normal AP or via BLE — never through the 802.11s
  interface.
- **Radio links are lossy.** A neighbor at the edge of range will
  form an 802.11s peering yet deliver a fraction of its frames.
  Expect link-quality effects that don't exist on wired Ethernet.
- **A client (STA) uplink on the same radio owns the channel.** The
  STA must follow whatever channel its upstream AP uses; every other
  interface on that radio follows the STA. A mesh pinned to a
  different channel silently never joins, and it does **not** recover
  when the STA disconnects — a `wifi reload` is needed (with fips 0.5.3
  or earlier, also a fips restart, since those versions do not rebind to
  the recreated mesh interface). A *roaming* uplink (travel-router /
  hotspot-chasing setups) is fundamentally incompatible with a
  fixed-channel mesh on the same radio: dedicate the mesh to the radio
  the STA never uses, and treat any mesh sharing a STA radio as
  best-effort.
