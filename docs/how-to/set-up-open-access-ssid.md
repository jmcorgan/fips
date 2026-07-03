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

## Why open, why RA-only

Three deliberate choices distinguish this from a stock guest network:

- **`encryption none`** — the SSID is open on purpose, and it *must*
  be. Clients key a saved network on SSID **plus security type**: if
  one router used a PSK and another OWE, the same `FIPS` name would be
  three different saved networks and roaming would break. Open is the
  only security type that needs zero provisioning, and OWE is left out
  for now for exactly this uniformity reason (OWE-transition mode is
  inconsistent across client vendors). Every FIPS peer link is already
  authenticated and encrypted by the Noise IK handshake — a stranger
  can associate, but their traffic dies at the FIPS handshake. What
  you concede: L2 metadata is visible in the air and a hostile radio
  can burn airtime — both true of any radio link.
- **No DHCP — IPv6 router advertisements only.** odhcpd announces a
  ULA prefix (`fd..`-range) for stateless SLAAC: no DHCPv4, no DHCPv6,
  no lease state. FIPS itself only needs link-local + mDNS, but
  Android's provisioning check requires an RA or a DHCP offer and
  *disconnects* with neither — RA-only is the minimum that satisfies
  it. The addressing is per-router and disposable: a roaming phone
  SLAACs a fresh address on each router, and the FIPS overlay
  identity, not the IP, is the mobility anchor.
- **Isolated interface** — its own network and firewall zone, with no
  path to `br-lan` and no forwarding to the WAN. Inbound traffic is
  rejected except ICMPv6 (SLAAC itself), mDNS, and the FIPS transport
  ports; the raw-Ethernet transport (EtherType 0x2121) is not IP and
  never traverses the firewall. AP client isolation is on, so clients
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

- OpenWrt 22.03+ with the FIPS package installed (fw4; odhcpd is part
  of the default images).
- Any radio — AP mode needs no special driver support.

## Step 1 — create the access point(s)

On **each** router, run the helper once per radio that should serve
clients:

```sh
fips-ap-setup radio0
```

This creates an open AP with SSID `!FIPS` and client isolation, an
isolated network with a static ULA `/64`, an RA-only odhcpd config
(SLAAC, no DHCP), and a locked-down `fips_ap` firewall zone — then
reloads the radio. Interfaces are named by radio index: `radio0` →
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
set network.fips_ap_radio0.ip6addr='fdxx:xxxx:xxxx:fa00::1/64'
set dhcp.fips_ap_radio0=dhcp
set dhcp.fips_ap_radio0.interface='fips_ap_radio0'
set dhcp.fips_ap_radio0.ra='server'
set dhcp.fips_ap_radio0.ra_default='2'
set dhcp.fips_ap_radio0.dhcpv6='disabled'
set dhcp.fips_ap_radio0.dhcpv4='disabled'
EOF
uci commit
wifi reload
```

plus the `fips_ap` firewall zone (input/forward REJECT, no
forwardings, ACCEPT rules for ICMPv6, UDP 5353/2121, TCP 8443).

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
ip -6 addr show dev fips-ap0    # the fd..::1/64 the router announces
```

No station entries means a radio problem; an association that drops
after ~30 s usually means the client never got an RA — check
`logread | grep odhcpd` and that the `dhcp.fips_ap_radio0` section
survived (`uci show dhcp | grep fips_ap`).

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
- **Strangers can associate — by design.** They reach only the FIPS
  handshake surface, which drops them. Do not add forwardings to the
  `fips_ap` zone: that would turn the open SSID into a hotspot and
  hand the isolation away.
- **Roaming is client-driven.** Clients decide when to hop BSSIDs
  (standard ESS behavior) and renumber on each router; FIPS sessions
  ride through because the overlay identity is the anchor. Expect a
  brief L2 gap during the hop, as on any ESS without 802.11r.
