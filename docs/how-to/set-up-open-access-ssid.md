# Set Up the Open FIPS Access SSID (OpenWrt)

Give phones and laptops a way in: every FIPS router broadcasts the
same open SSID — `!FIPS` — from its access radio. Same SSID + unique
BSSIDs is one standard ESS, so a client saves the network once and
roams between all FIPS routers natively, with no per-router setup and
no shared credentials (the Freifunk model). The leading `!` sorts the
network to the top of alphabetically ordered pickers (iOS, desktop
OSes — Android sorts by signal strength) and is part of the name:
SSIDs match byte-for-byte or not at all. The radio layer provides
nothing but open L2 to the nearest router; FIPS provides everything
else: encryption and authentication (Noise IK), discovery
(mDNS/Ethernet beacons), and mobility (the overlay identity survives
roaming, so no 802.11r or L2 tricks are needed).

This is the *access* layer — how clients reach FIPS routers. For the
router-to-router *backhaul*, see
[set-up-80211s-mesh-backhaul.md](set-up-80211s-mesh-backhaul.md).
For all `transports.ethernet.*` configuration keys, see
[../reference/configuration.md](../reference/configuration.md).

## Why open, why this addressing

Three deliberate choices distinguish this from a stock guest network:

- **`encryption none`** — the SSID is open on purpose, and it *must*
  be. Clients key a saved network on SSID **plus security type**: if
  one router used a PSK and another OWE, the same `FIPS` name would be
  three different saved networks and roaming would break. Open is the
  only security type that needs zero provisioning, and OWE is left out
  for now for exactly this uniformity reason (OWE-transition mode is
  inconsistent across client vendors). Every FIPS peer link is already
  authenticated and encrypted by the Noise IK handshake. A stranger
  can associate *and* form a FIPS peer link — that is the point of open
  access; the handshake authenticates each link (no impersonation, no
  MITM) but does not gate who may peer, and admission is open up to the
  daemon's max-peers cap. What confines a hostile peer is the isolated
  `fips_ap` zone (no path to br-lan or the WAN — see below), not the
  handshake. What you concede: any nearby device can reach the FIPS
  overlay surface (handshake, discovery, lookup, routing) and peer with
  the router; L2 metadata is visible in the air; a hostile radio can
  burn airtime — all inherent to an open radio link.
- **DHCPv4 from a fixed subnet, plus IPv6 router advertisements.**
  dnsmasq leases IPv4 out of `10.21.<N>.0/24` (`N` = the radio index;
  the prefix echoes FIPS port 2121). The subnet is deliberately
  **identical on every router**: a roaming phone keeps its lease
  across routers, and dnsmasq's authoritative mode (the OpenWrt
  default, pinned by the helper) ACKs a renew the new router never
  issued. odhcpd additionally announces a ULA prefix (`fd..`-range)
  for stateless SLAAC; DHCPv6 stays off. FIPS itself only needs
  link-local + mDNS, but Android's provisioning check requires an RA
  or a DHCP offer and *disconnects* with neither, and plain laptops
  expect a real IPv4 address. Works with or without an upstream —
  nothing here depends on the WAN. The IPv6 side stays per-router and
  disposable; in all cases the FIPS overlay identity, not the IP, is
  the mobility anchor.
- **Isolated interface** — its own network and firewall zone, with no
  path to `br-lan` and no forwarding to the WAN. Inbound traffic is
  rejected except DHCPv4, ICMPv6 (SLAAC itself), mDNS, and the FIPS
  transport ports; the raw-Ethernet transport (EtherType 0x2121) is
  not IP and never traverses the firewall. AP client isolation is on, so clients
  cannot reach each other at L2 — two FIPS phones on one router still
  reach each other through the router at the overlay layer.

## The "no internet" behavior (expected, one-time acceptance)

The network intentionally provides **no internet**. On first connect,
a phone's validation probe fails and it asks whether to stay on a
network without internet access — choose **stay connected** and
**don't ask again**. That choice is stored per SSID, so accepting it
once covers every FIPS router anywhere.

After that, the network is marked "connected, no internet"
(unvalidated) and the phone keeps **cellular as its default route**
while staying associated — normal apps never notice the FIPS network
exists. FIPS apps bind their sockets to the Wi-Fi network explicitly,
so mesh traffic flows over Wi-Fi while everything else uses cellular.

## When to use

- Any FIPS router that should serve phones and laptops directly, not
  just peer with other routers.
- You want clients to roam between FIPS routers with zero per-router
  or per-site configuration.

It is the complement of the 802.11s backhaul: the backhaul links
routers (clients cannot join it), the access SSID admits clients.
Both can share a radio, at an airtime cost (see constraints).

## Requirements

- OpenWrt 22.03+ with the FIPS package installed (fw4; dnsmasq and
  odhcpd are part of the default images).
- Any radio — AP mode needs no special driver support.

## Step 1 — create the access point(s)

On **each** router, run the helper once per radio that should serve
clients:

```sh
fips-ap-setup radio0
```

This creates an open AP with SSID `!FIPS` and client isolation, an
isolated network with `10.21.<N>.1/24` and a static ULA `/64`, a
DHCPv4 + RA dhcp config (dnsmasq leases, SLAAC, no DHCPv6), and a
locked-down `fips_ap` firewall zone — then reloads the radio. Interfaces are named by radio index: `radio0` →
`fips-ap0`, `radio1` → `fips-ap1`. Pass a second argument to use a
different SSID — but the SSID, like the security type, must be
identical on **all** routers or clients will treat them as separate
networks and stop roaming.

On dual-band routers, run it for both radios so clients can pick
either band:

```sh
fips-ap-setup radio0
fips-ap-setup radio1
```

**Channels are free per router.** Unlike the mesh backhaul, there is
no same-channel constraint — clients scan when they roam — so leave
each router on whatever channel suits its RF environment.

Equivalent manual UCI (per radio), if you prefer to see what it does
(`fdxx:...` stands for a `/64` out of the router's ULA prefix):

```sh
uci batch <<'EOF'
set wireless.fips_ap_radio0=wifi-iface
set wireless.fips_ap_radio0.device='radio0'
set wireless.fips_ap_radio0.mode='ap'
set wireless.fips_ap_radio0.ssid='!FIPS'
set wireless.fips_ap_radio0.encryption='none'
set wireless.fips_ap_radio0.isolate='1'
set wireless.fips_ap_radio0.ifname='fips-ap0'
set wireless.fips_ap_radio0.network='fips_ap_radio0'
set network.fips_ap_radio0=interface
set network.fips_ap_radio0.proto='static'
set network.fips_ap_radio0.ipaddr='10.21.0.1'
set network.fips_ap_radio0.netmask='255.255.255.0'
set network.fips_ap_radio0.ip6addr='fdxx:xxxx:xxxx:fa00::1/64'
set dhcp.fips_ap_radio0=dhcp
set dhcp.fips_ap_radio0.interface='fips_ap_radio0'
set dhcp.fips_ap_radio0.ra='server'
set dhcp.fips_ap_radio0.ra_default='2'
set dhcp.fips_ap_radio0.dhcpv6='disabled'
set dhcp.fips_ap_radio0.dhcpv4='server'
set dhcp.fips_ap_radio0.start='10'
set dhcp.fips_ap_radio0.limit='200'
EOF
uci commit
wifi reload
```

plus the `fips_ap` firewall zone (input/forward REJECT, no
forwardings, ACCEPT rules for DHCPv4/UDP 67, ICMPv6, UDP 5353/2121,
TCP 8443).

## Step 2 — check the FIPS transport binding

The `fips.yaml` shipped in the OpenWrt package carries one transport
entry per access interface, but **commented out** — so a stock install
that never runs this helper logs no per-boot "interface missing"
warning. `fips-ap-setup` uncommented the matching `apN` entry in Step 1,
so there is normally nothing to do here. If you maintain your own config
(or ran the manual UCI above instead of the helper), make sure the
entries are present and uncommented:

```yaml
transports:
  ethernet:
    ap0:
      interface: "fips-ap0"
      discovery: true
      announce: true
      auto_connect: true
      accept_connections: true
    ap1:
      interface: "fips-ap1"
      discovery: true
      announce: true
      auto_connect: true
      accept_connections: true
```

## Step 3 — restart the daemon (order matters)

```sh
/etc/init.d/fips restart
```

Restart fips **after** the AP interface is up. A transport whose
interface is missing at startup is logged and skipped, not retried —
so if the daemon comes up before the radio, the access transport
stays dead until the next restart. (An interface that *vanishes and
returns* after startup is recovered automatically; only the missing-
at-startup case needs this ordering.)

## Verify

L2 and addressing first, with a phone or laptop connected to `!FIPS`:

```sh
iw dev fips-ap0 station dump    # one entry per associated client
ip addr show dev fips-ap0       # 10.21.0.1/24 and the fd..::1/64
cat /tmp/dhcp.leases            # one lease per connected client
```

No station entries means a radio problem; an association that drops
after ~30 s usually means the client never got an address — check
`logread | grep -e dnsmasq -e odhcpd` and that the
`dhcp.fips_ap_radio0` section survived
(`uci show dhcp | grep fips_ap`).

Then the FIPS layer on top, for a client running FIPS:

```sh
logread | grep -i beacon        # beacons flowing on the new transport
fipsctl show peers              # client authenticated and connected
```

On the phone itself: the network shows "connected, no internet" and
stays associated — that is the designed steady state, not an error.

## Constraints

- **SSID and security type must be uniform across ALL routers.**
  One router with a PSK (or OWE) under the same name splits the ESS
  into different saved networks and silently breaks roaming. Never
  "harden" a single router.
- **Airtime is shared per radio.** An access AP and a mesh backhaul
  on the same radio share one channel. On dual/tri-band hardware,
  dedicate a band to the backhaul and serve clients on the others.
- **Strangers can associate and peer — by design.** Open access means
  any nearby device can complete the Noise handshake and become a FIPS
  peer (up to the max-peers cap); the handshake authenticates each link,
  it does not restrict who joins. They reach only the FIPS overlay
  surface — the isolated zone gives no path to br-lan or the WAN. Do not
  add forwardings to the `fips_ap` zone: that would turn the open SSID
  into a hotspot and hand the isolation away.
- **Roaming is client-driven.** Clients decide when to hop BSSIDs
  (standard ESS behavior); the IPv4 lease survives the hop (same
  subnet everywhere), the SLAAC address renumbers, and FIPS sessions
  ride through because the overlay identity is the anchor. Expect a
  brief L2 gap during the hop, as on any ESS without 802.11r.
- **The `10.21.<N>.0/24` convention must hold everywhere.** Lease
  survival depends on every router serving the same subnet from the
  same radio index — the helper guarantees this; don't hand-pick
  per-router subnets. Two routers can lease the same address to two
  different clients; after a roam the conflict is caught (dnsmasq
  NAKs a renew for an address in use) and the client re-DHCPs. If a
  laptop is *also* wired to a LAN that really uses `10.21.<N>.0/24`,
  its routing table will conflict — a corner case worth knowing, not
  designing around: the zone forwards nowhere, so the FIPS side never
  reaches beyond the router either way.
