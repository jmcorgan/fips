# FIPS FreeBSD packaging

Builds a native FreeBSD `.pkg` shipping `fips`, `fipsctl`, `fipstop`,
rc.d services, and `.fips` DNS integration. `fips-gateway` is excluded
(its NAT backend is nftables, Linux-only).

Platform notes: the Ethernet and BLE transports are not available on
FreeBSD (UDP, TCP, Tor, and Nym are). The UDP datapath deliberately
uses the portable single-packet receive loop — FreeBSD's `recvmmsg(2)`
is a libc loop over `recvmsg`, not a kernel batch, so the Linux/macOS
batched arm would gain nothing — and the connected-UDP fast path is
not compiled pending FreeBSD-specific `SO_REUSEPORT` validation.

## Build

```sh
./packaging/freebsd/build-pkg.sh            # cargo build --release + pkg create
./packaging/freebsd/build-pkg.sh --no-build # package existing release binaries
```

Output: `deploy/fips-<version>-freebsd-<arch>.pkg` (e.g.
`fips-0.5.0.dev-freebsd-amd64.pkg` — pkg versions cannot contain `-`).

## Install

```sh
pkg add ./deploy/fips-0.5.0.dev-freebsd-amd64.pkg
# post-install seeds this from the sample if absent, at mode 0600
vi /usr/local/etc/fips/fips.yaml
sysrc fips_enable=YES fips_dns_enable=YES
service fips start
service fips_dns start
fipsctl show status
```

Config installs sample-style (`@sample` semantics via manifest
scripts), so an edited `fips.yaml` survives upgrade/removal.
`fips.yaml` is installed `0600` — it may hold the node's private key
(`nsec:`). The daemon runs under daemon(8) with pidfile
`/var/run/fips/fips.pid` and logs to `/var/log/fips.log` (rc.conf
knobs: `fips_config`, `fips_flags`, `fips_logfile`).

The package creates a `fips` group; members can run `fipsctl` and
`fipstop` without root (`pw groupmod fips -m <user>`, then re-login).
On `pkg upgrade` the services are stopped before the binaries are
replaced and started again afterwards if enabled; on `pkg delete` they
are stopped and the `.fips` resolver drop-in is removed.

## .fips DNS integration

The daemon answers `.fips` queries on `[::1]:5354`. `fips_dns` points
the system resolver's `fips.` zone there; backends tried in order:
base `local_unbound` (drop-in `/var/unbound/conf.d/fips.conf`), pkg
`unbound`, pkg `dnsmasq`. The unbound drop-in must (and does) set:

- `do-not-query-localhost: no` — unbound's default silently refuses
  loopback forwarders, SERVFAILing every `.fips` query.
- `do-ip6: yes` — the daemon binds `::1` only.
- `domain-insecure: "fips."` — the zone is unsigned.

### One-time host resolver setup (NOT automated)

The package configures the `fips.` zone only; making the local
resolver the *system* resolver is an operator decision. On a typical
box:

```sh
sysrc local_unbound_enable=YES
local-unbound-setup 1.1.1.1 9.9.9.9   # explicit upstreams — see below
service local_unbound restart
```

Field-tested caveats (`fips-dns-setup` detects and warns about each):

- `/etc/resolv.conf` must list a loopback nameserver (ideally only
  `127.0.0.1`), or nothing ever queries unbound and `.fips` cannot
  resolve.
- **Do not use a home-router DNS proxy as unbound's upstream.** Many
  CPE forwarders are EDNS-broken; unbound always sends EDNS, so every
  public query SERVFAILs. Forward to real resolvers (ISP or public).
- Remove `options edns0` from `/etc/resolv.conf` if present, and set
  `resolv_conf_options=""` in `/etc/resolvconf.conf` so resolvconf(8)
  does not re-add it — against an EDNS-broken router it breaks libc
  resolution outright.
- Never run `local-unbound-setup` with no arguments while resolv.conf
  already points at 127.0.0.1 — it snapshots that as upstream and
  forwards unbound to itself.

## Debugging

```sh
drill -p 5354 <npub>.fips @::1 AAAA   # daemon directly (bypasses unbound)
drill <npub>.fips AAAA                # full chain; SERVER: must be 127.0.0.1
cat /var/run/fips/dns-backend         # which backend fips_dns configured
```

The TUN interface gets a kernel-assigned name (`tun0`, `tun1`, ...),
like `utun` on macOS, and is destroyed automatically when the daemon
exits. `ifconfig <name>` prints `Opened by PID <n>` for the process
holding a tun device.
