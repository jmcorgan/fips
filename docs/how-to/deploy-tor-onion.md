# Deploy a Tor Onion Service for FIPS

This guide covers running a Tor onion service that accepts inbound
FIPS peer connections.

For the Tor transport's design and the bridge-node pattern (running
Tor and UDP simultaneously), see
[../design/fips-transport-layer.md](../design/fips-transport-layer.md).
For the full `transports.tor.*` config knob inventory, see
[../reference/configuration.md](../reference/configuration.md).

## Inbound modes

FIPS supports two inbound Tor modes. (A third mode, `socks5`, is
outbound-only and not covered here.)

- **`directory` mode** *(recommended)*. Tor manages the onion
  service via `HiddenServiceDir` and `HiddenServicePort` directives
  in `torrc`. FIPS reads the resulting `.onion` hostname from a
  file and binds a local TCP listener for Tor to forward inbound
  connections to. No control-port interaction is required, which
  makes this mode compatible with Tor's `Sandbox 1` seccomp-bpf
  hardening.
  - **`torrc` requires:** `HiddenServiceDir` + `HiddenServicePort`.
- **`control_port` mode**. FIPS speaks to Tor's control port to
  create an ephemeral onion service at startup (`ADD_ONION`). The
  onion key lives only for the lifetime of the FIPS daemon's
  control-port session. This mode is **incompatible** with
  `Sandbox 1` — the sandbox forbids control-port-driven onion
  service management.
  - **`torrc` requires:** `ControlPort` (typically the Unix socket
    `/run/tor/control`) and a usable auth method
    (`CookieAuthentication 1` is the common choice).

Pick `directory` unless you have a specific reason to prefer
`control_port`. The rest of this guide covers `directory` mode
end-to-end.

## Prerequisites

- Tor daemon installed and running (Debian/Ubuntu: `apt install tor`)
- FIPS daemon configured and able to start
- Operator access to `/etc/tor/torrc` (or a drop-in under
  `/etc/tor/torrc.d/`)

## Step 1: Configure Tor's HiddenServiceDir

Add the following to `/etc/tor/torrc`:

```text
HiddenServiceDir /var/lib/tor/fips
HiddenServicePort 8443 127.0.0.1:8444
```

`HiddenServiceDir` tells Tor where to store the onion service's
private key and `hostname` file. `HiddenServicePort` declares that
inbound TCP traffic to port 8443 of the onion address should be
forwarded to `127.0.0.1:8444` on the local host — that is where FIPS
will bind its listener.

The external port (`8443` here) is what peers will connect to over
Tor; the internal target (`127.0.0.1:8444`) is purely local and is
not directly reachable from the network.

## Step 2: Reload Tor and read the onion hostname

```sh
sudo systemctl reload tor@default     # or `tor` on systems without instance support
```

After Tor processes the new config, the hostname file appears:

```sh
sudo cat /var/lib/tor/fips/hostname
# xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion
```

Tor regenerates the onion key only on first run (or if you remove
`HiddenServiceDir`). The `hostname` value is stable across daemon
restarts as long as `HiddenServiceDir` is preserved.

## Step 3: Verify HiddenServiceDir permissions

The directory must be readable only by the Tor user (Tor refuses to
start otherwise):

```sh
ls -la /var/lib/tor/fips
# drwx------ debian-tor debian-tor ...
```

With the shipped Debian systemd unit, FIPS runs as root and reads
the `hostname` file directly — no permission adjustment is needed.

### Non-default deployments

If you run FIPS as an unprivileged user (custom packaging,
hardened deployment, etc.), the FIPS daemon user needs read access
to `hostname`. Options:

- Add the FIPS user to the `debian-tor` group and loosen group
  read on `HiddenServiceDir` (Tor still requires the directory
  itself to be `0700`, so this typically means making `hostname`
  itself group-readable rather than the directory).
- Read `hostname` once at startup as root, then drop privileges.
- Copy the hostname into a path the FIPS user can read, refreshed
  whenever the onion key changes.

## Step 4: Configure the FIPS Tor transport

In `/etc/fips/fips.yaml`, configure `transports.tor` with `mode:
directory`:

```yaml
transports:
  tor:
    mode: directory
    socks5_addr: "127.0.0.1:9050"
    connect_timeout_ms: 120000
    mtu: 1400
    advertised_port: 8443
    directory_service:
      hostname_file: "/var/lib/tor/fips/hostname"
      bind_addr: "127.0.0.1:8444"
```

The `bind_addr` must match the *target* of the `HiddenServicePort`
directive in `torrc`. The `hostname_file` path must match
`HiddenServiceDir` plus `/hostname`.

`advertised_port` is the *virtual* onion port peers dial — i.e. the
first number on the `HiddenServicePort` line, **not** the local
target. The default is `443`; this guide uses `8443` on both sides
to match the `HiddenServicePort 8443 127.0.0.1:8444` example
above. Setting this explicitly is important if you ever flip
`advertise_on_nostr: true`: the published advert otherwise
defaults to `tor:<hash>.onion:443`, which won't match the actual
onion port.

The `socks5_addr` is the Tor SOCKS5 proxy used for *outbound*
connections to other onion services or clearnet endpoints (separate
from inbound onion service handling).

Optional monitoring knobs: `control_addr` and `control_auth` (e.g.
`/run/tor/control` and `cookie`) let the daemon read Tor's status
through the control port even in `directory` mode. They are
non-fatal on failure — the onion service still works without them.
See [../reference/configuration.md](../reference/configuration.md)
for the full key list and examples.

## Step 5: Reload the FIPS daemon

```sh
sudo systemctl reload-or-restart fips
```

At startup the daemon reads the `.onion` hostname from
`hostname_file`, binds `127.0.0.1:8444`, and announces the onion
endpoint internally. From this point inbound connections to
`<your-onion>.onion:8443` arrive at FIPS over Tor.

## Step 6: Verify

Check that the FIPS daemon log shows the onion endpoint at startup:

```sh
sudo journalctl -u fips -e | grep -i 'onion\|directory'
```

You should see a line indicating the onion address FIPS will accept
inbound connections on, and that the local bind on `127.0.0.1:8444`
succeeded.

From another node configured with the Tor transport in `socks5` or
`directory` mode, attempt to dial:

```sh
fipsctl connect <peer-npub-or-hostname> <your-onion>.onion:8443 tor
```

A successful `fipsctl show peers` afterwards on the inbound side
shows the new peer with `transport=tor`.

## Optional: advertise the onion endpoint via Nostr discovery

If `node.discovery.nostr.enabled: true`, set
`transports.tor.advertise_on_nostr: true` so the onion endpoint
appears in this node's published advert. See
[enable-nostr-discovery.md](enable-nostr-discovery.md) Scenario 2.

## Troubleshooting

- **Tor refuses to start with `Sandbox 1` and onion-service errors.**
  `Sandbox 1` requires `directory` mode and forbids creating onion
  services through the control port. Verify your `torrc` uses
  `HiddenServiceDir` (this guide), not `ADD_ONION` via control port.
- **FIPS daemon fails to bind `127.0.0.1:8444`.** Another process is
  already bound to that port. Either stop the conflicting process or
  pick a different port and update both `torrc`'s
  `HiddenServicePort` target and `fips.yaml`'s `bind_addr` to match.
- **Onion hostname is empty or missing.** Check `journalctl -u tor`
  for permission errors on `HiddenServiceDir`. The directory must be
  owned by the Tor user with mode `0700`.
- **FIPS daemon cannot read `hostname_file`.** File is owned by the
  Tor user and not readable by the FIPS daemon user. Adjust
  permissions, or copy the hostname into a path the FIPS user can
  read.

## See also

- [../design/fips-transport-layer.md](../design/fips-transport-layer.md)
  — Tor transport design, three modes (`socks5`, `control_port`,
  `directory`), bridge-node pattern
- [../reference/configuration.md](../reference/configuration.md) —
  full `transports.tor.*` configuration knob table
- [enable-nostr-discovery.md](enable-nostr-discovery.md) — Scenario 2
  for advertising the onion endpoint to peers via Nostr
