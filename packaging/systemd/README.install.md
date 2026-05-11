# FIPS Installation Guide

## Quick Start

```bash
tar xzf fips-*-linux-*.tar.gz
cd fips-*-linux-*/
sudo ./install.sh
```

## What Gets Installed

| File | Location |
|------|----------|
| fips (daemon) | /usr/local/bin/fips |
| fipsctl (CLI) | /usr/local/bin/fipsctl |
| fipstop (TUI) | /usr/local/bin/fipstop |
| fips-gateway (LAN bridge) | /usr/local/bin/fips-gateway |
| Configuration | /etc/fips/fips.yaml |
| Identity key | /etc/fips/fips.key (auto-generated) |
| Public key | /etc/fips/fips.pub (auto-generated) |
| Hosts file | /etc/fips/hosts |
| Firewall baseline | /etc/fips/fips.nft |
| Firewall drop-in directory | /etc/fips/fips.d/ |
| Daemon unit | /etc/systemd/system/fips.service (enabled) |
| DNS routing unit | /etc/systemd/system/fips-dns.service (enabled) |
| Gateway unit | /etc/systemd/system/fips-gateway.service (NOT enabled) |
| Firewall unit | /etc/systemd/system/fips-firewall.service (NOT enabled) |
| DNS helpers | /usr/lib/fips/fips-dns-{setup,teardown} |

A system group `fips` is created for control socket access. By
default, only `fips.service` and `fips-dns.service` are enabled at
install time. `fips-gateway.service` and `fips-firewall.service`
are installed but require explicit operator opt-in (see the
sections below).

## Post-Install Configuration

Edit `/etc/fips/fips.yaml` before starting the service.

### 1. Identity

By default, the node generates a new ephemeral identity on each start
for privacy. If the node's npub will be published for others to use as a
static peer, enable a stable identity by uncommenting `persistent: true`
in the identity section:

```yaml
node:
  identity:
    persistent: true
```

On first start with persistence enabled, a keypair is auto-generated and saved:

- `/etc/fips/fips.key` (mode 0600) — secret key
- `/etc/fips/fips.pub` (mode 0644) — public key (npub)

The same identity is reused on subsequent starts. Alternatively, set
`node.identity.nsec` to use a specific key.

### 2. Ethernet Transport

If using Ethernet for local mesh discovery, uncomment the ethernet section
and set the interface name:

```yaml
transports:
  ethernet:
    interface: "eth0"
    discovery: true
    announce: true
    auto_connect: true
    accept_connections: true
```

### 3. Bluetooth Transport

If using BLE for local mesh discovery, the FIPS binary must be built with
the `ble` feature (enabled by default). BlueZ must be installed and running:

```bash
sudo apt install bluez
sudo systemctl enable --now bluetooth
```

Add your service user to the `bluetooth` group, or run with
`CAP_NET_ADMIN` + `CAP_NET_RAW` capabilities.

Configure BLE in the transports section:

```yaml
transports:
  ble:
    adapter: "hci0"
    advertise: true
    scan: true
    auto_connect: true
    accept_connections: true
```

### 4. Static Peers

For bootstrapping over UDP or TCP, add known peers:

```yaml
peers:
  - npub: "npub1..."
    alias: "gateway"
    addresses:
      - transport: udp
        addr: "test-us01.fips.network:2121"  # IP or hostname (e.g., "peer.example.com:2121")
    connect_policy: auto_connect
```

### 5. DNS Resolver

FIPS includes a DNS responder for `.fips` domain names that listens on
`fips0` and on `[::1]:5354`. The `fips-dns.service` helper detects the
host's DNS routing system and configures it to forward `.fips` queries
to the responder. Backends tried in order:

1. systemd `dns-delegate` drop-in (systemd >= 258, declarative)
2. `systemd-resolved` global drop-in via `/etc/systemd/resolved.conf.d/`
3. `systemd-resolved` per-link `resolvectl` (legacy fallback)
4. `dnsmasq` (standalone, drops a config in `/etc/dnsmasq.d/`)
5. NetworkManager with the `dnsmasq` plugin

If none of the supported backends is detected, `fips-dns-setup` logs a
warning with manual instructions and exits cleanly. The daemon itself
keeps working; only the host's `.fips` resolution is left unwired.

The installer enables `fips-dns.service` automatically. To disable
or re-enable later:

```bash
sudo systemctl disable --now fips-dns.service   # disable
sudo systemctl enable --now fips-dns.service    # re-enable
```

### 6. Mesh-interface firewall baseline (optional)

`fips.nft` is a default-deny baseline for inbound traffic on the
`fips0` mesh interface. It is shipped as `/etc/fips/fips.nft` (not
loaded by default) along with a disabled `fips-firewall.service`
unit. Enable it explicitly:

```bash
sudo systemctl enable --now fips-firewall.service
```

The baseline polices only `fips0`, leaving Docker, Tor, the host
firewall, and other interfaces untouched. Outbound from `fips0` is
unrestricted; inbound is dropped except for replies to outbound
flows, ICMPv6 echo-request, and any operator drop-ins under
`/etc/fips/fips.d/*.nft`. Read the comments at the top of
`/etc/fips/fips.nft` for the full policy and how to add per-service
allow rules.

### 7. Outbound LAN gateway (optional)

`fips-gateway` bridges unmodified LAN hosts to `.fips` destinations
through a DNS-allocated virtual IPv6 pool and kernel nftables NAT.
The binary is installed at `/usr/local/bin/fips-gateway` and a
`fips-gateway.service` unit ships disabled by default.

To enable it, configure the gateway block in `/etc/fips/fips.yaml`,
then:

```bash
sudo systemctl enable --now fips-gateway.service
```

The unit `Requires=fips.service`, waits up to 30 seconds for `fips0`
to come up, and runs `fips-gateway --config /etc/fips/fips.yaml`.
Inbound port-forward rules can be added in the same `gateway:`
block.

## Firewall Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 2121 | UDP | Peer-to-peer mesh traffic |
| 8443 | TCP | Inbound peer connections |

## Service Management

The install ships four units. `fips.service` and `fips-dns.service`
are enabled at install time. `fips-gateway.service` and
`fips-firewall.service` are installed but disabled until the
operator opts in.

```bash
# Daemon
sudo systemctl start fips
sudo systemctl stop fips
sudo systemctl restart fips

# DNS routing helper
sudo systemctl restart fips-dns

# Optional services (opt-in)
sudo systemctl enable --now fips-firewall   # mesh-interface nftables baseline
sudo systemctl enable --now fips-gateway    # outbound LAN gateway

# View logs (any of the units above)
sudo journalctl -u fips -f
sudo journalctl -u fips-gateway -f
sudo journalctl -u fips-firewall -f

# Switch to debug logging
sudo systemctl set-environment RUST_LOG=debug
sudo systemctl restart fips
```

## Monitoring

```bash
# Quick status
fipsctl show status

# Interactive dashboard
fipstop

# Other queries
fipsctl show peers
fipsctl show links
fipsctl show sessions
fipsctl show routing
fipsctl show transports
```

## Non-Root Access to fipsctl/fipstop

Add your user to the `fips` group:

```bash
sudo usermod -aG fips $USER
```

Log out and back in for the group change to take effect.

## Uninstall

```bash
# Remove binaries and service, keep configuration
sudo ./uninstall.sh

# Remove everything including /etc/fips/ and the fips group
sudo ./uninstall.sh --purge
```
