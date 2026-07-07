# Set Up an 802.11s Mesh Backhaul (OpenWrt)

Link FIPS routers over radio — no cables, no APs, no shared
infrastructure — by running the Ethernet transport on an open 802.11s
mesh interface. The radio layer provides nothing but L2 frames to
direct neighbors; FIPS provides everything else: encryption and
authentication (Noise IK), peer discovery (Ethernet beacons), and
routing (the spanning tree).

For the transport design, see
[../design/fips-transport-layer.md](../design/fips-transport-layer.md).
For all `transports.ethernet.*` configuration keys, see
[../reference/configuration.md](../reference/configuration.md).

## Why open, why forwarding off

Two deliberate choices distinguish this from a stock 802.11s setup:

- **`encryption none`** — the mesh is open on purpose. Every FIPS peer
  link is already authenticated and encrypted by the Noise IK
  handshake, so SAE at L2 would duplicate that work, add a shared
  credential to provision across routers, and (on ath10k) force the
  firmware into its slower raw Tx/Rx mode. A stranger can form an
  802.11s peering with your router, but their frames die at the FIPS
  handshake — the same security model as mDNS and BLE discovery, where
  the advert is only a hint and the handshake is the authentication.
  What you concede: L2 metadata (MAC addresses, frame sizes) is
  visible in the air, and a hostile radio can burn airtime — both true
  of any radio link regardless of L2 encryption.
- **`mesh_fwding 0`** — disables 802.11s's own HWMP routing so each
  mesh link is a plain neighbor link. FIPS is the routing layer; two
  routing layers would fight, and broadcast discovery beacons would
  flood the whole mesh instead of reaching direct neighbors only.

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

This creates an open 802.11s interface with mesh ID `fips-mesh` and
HWMP forwarding off, attaches it to an unmanaged netifd interface (no
IP configuration — none is needed), and reloads the radio. Interfaces
are named by radio index: `radio0` → `fips-mesh0`, `radio1` →
`fips-mesh1`. Pass a second argument to use a different mesh ID.

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
set wireless.fips_mesh_radio1.ifname='fips-mesh1'
set wireless.fips_mesh_radio1.network='fips_mesh_radio1'
set network.fips_mesh_radio1=interface
set network.fips_mesh_radio1.proto='none'
EOF
uci commit
wifi reload
```

## Step 2 — check the FIPS transport binding

The `fips.yaml` shipped in the OpenWrt package already carries one
transport entry per radio, enabled by default — each is inert until
its interface exists. If you maintain your own config, make sure they
are present:

```yaml
transports:
  ethernet:
    mesh0:
      interface: "fips-mesh0"
      discovery: true
      announce: true
      auto_connect: true
      accept_connections: true
    mesh1:
      interface: "fips-mesh1"
      discovery: true
      announce: true
      auto_connect: true
      accept_connections: true
```

## Step 3 — restart the daemon (order matters)

```sh
/etc/init.d/fips restart
```

Restart fips **after** the mesh interface is up. A transport whose
interface is missing at startup is logged and skipped, not retried —
so if the daemon comes up before the radio, the mesh transport stays
dead until the next restart. (An interface that *vanishes and
returns* after startup is recovered automatically; only the missing-
at-startup case needs this ordering.)

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
   (mesh ID typo, or one side has encryption set). Nothing visible →
   check `wifi status` on the other router, remember the ~60 s DFS
   CAC wait, and confirm the country code is set
   (`uci get wireless.radio1.country`) — an unset regdomain can
   block channels entirely.
4. `logread | grep -iE "mesh|fips-mesh0"` on both sides.

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
  when the STA disconnects — a `wifi reload` (plus a fips restart) is
  needed. A *roaming* uplink (travel-router / hotspot-chasing setups)
  is fundamentally incompatible with a fixed-channel mesh on the same
  radio: dedicate the mesh to the radio the STA never uses, and treat
  any mesh sharing a STA radio as best-effort.
