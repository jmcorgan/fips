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
| Configuration | /etc/fips/fips.yaml |
| Identity key | /etc/fips/fips.key (auto-generated) |
| Public key | /etc/fips/fips.pub (auto-generated) |
| systemd unit | /etc/systemd/system/fips.service |

A system group `fips` is created for control socket access.

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

### 3. Static Peers

For bootstrapping over UDP or TCP, add known peers:

```yaml
peers:
  - npub: "npub1..."
    alias: "gateway"
    addresses:
      - transport: udp
        addr: "217.77.8.91:2121"  # public FIPS testing node
    connect_policy: auto_connect
```

### 4. DNS Resolver

FIPS includes a DNS responder for `.fips` domain names (port 5354).
To integrate with systemd-resolved:

```bash
sudo resolvectl dns fips0 127.0.0.1:5354
sudo resolvectl domain fips0 ~fips
```

To make this persistent, create a systemd-networkd override or add a
drop-in for the fips0 interface.

## Firewall Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 2121 | UDP | Peer-to-peer mesh traffic |
| 8443 | TCP | Inbound peer connections |

## Service Management

```bash
# Start / stop / restart
sudo systemctl start fips
sudo systemctl stop fips
sudo systemctl restart fips

# View logs
sudo journalctl -u fips -f

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
