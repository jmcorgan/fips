# WireGuard Sidecar For macOS

This example lets macOS reach the FIPS mesh through a local Docker container.

## Files

- `fips-on.sh`: user-facing startup wrapper
- `fips-host.sh`: small privileged helper for macOS networking
- `fips-off.sh`: teardown wrapper
- `entrypoint-sidecar.sh`: container startup logic
- `identity/fips.key` and `identity/fips.pub`: generated persistent sidecar identity
- `fips.yaml`: FIPS node config used inside the container

## Configure Peers

Before first use, replace the placeholder bootstrap peer in `fips.yaml` with a real peer for the mesh you want to join.

## Startup Flow

```text
macOS user        fips-on.sh      Docker / wireguard-sidecar     fips-host.sh (sudo)
    |                 |                        |                         |
    | ./fips-on.sh    |                        |                         |
    |---------------> |                        |                         |
    |                 | generate fips.key      |                         |
    |                 | generate client keys   |                         |
    |                 |----------------------->| bind-mount identity/    |
    |                 | start/recreate container                         |
    |                 |----------------------->| entrypoint starts        |
    |                 |                        | generate server keys     |
    |                 |                        | wait for client.pub      |
    |                 |                        | bring up wg0             |
    |                 | poll `wg show wg0`    |                         |
    |                 |<-----------------------|                         |
    |                 | sudo fips-host.sh on  |                         |
    |                 |------------------------------------------------->|
    |                 |                        | write /etc/wireguard     |
    |                 |                        | wg-quick up fips0        |
    |                 |                        | write /etc/resolver/fips |
    |                 |                        | flush DNS                |
    |                 |<-------------------------------------------------|
    | ready           |                        |                         |
```

## What `fips-on.sh` Does

1. Creates `identity/` and `identity/wireguard/` if needed.
2. Generates `identity/fips.key` and `identity/fips.pub` with `fipsctl keygen --dir /etc/fips` if the sidecar does not already have a persistent identity.
3. Generates the host WireGuard client keypair if missing.
4. Fixes ownership on the generated client key files so the Docker bind mount stays readable on macOS.
5. Starts `wireguard-sidecar` with `docker compose up -d --build --force-recreate`.
6. Waits until the container has created and brought up `wg0`.
7. Calls the privileged helper to configure host networking:
   - writes `/etc/wireguard/fips0.conf`
   - runs `wg-quick up fips0`
   - writes `/etc/resolver/fips`
   - flushes macOS DNS caches

## What Happens In The Container

`entrypoint-sidecar.sh`:

1. Generates the server WireGuard keypair on first run.
2. Waits briefly for `identity/wireguard/client.pub` from the host.
3. Writes the container-side `wg0` config.
4. Brings up `wg0` on UDP port `51820`.
5. Starts `fips --config /etc/fips/fips.yaml` using the bind-mounted `identity/fips.key`.
6. Enables forwarding and NAT66 from `wg0` toward `fips0` for FIPS
   `fd00::/8` destinations only.

Only FIPS traffic for `fd00::/8` is forwarded through the sidecar. Regular
internet traffic still uses the macOS host network and does not route through
`wg0` or `fips0`.

## Sidecar FIPS Identity

`fips-on.sh` generates `identity/fips.key` and `identity/fips.pub` on first run by calling:

```bash
docker run --rm \
  --entrypoint fipsctl \
  -v "$PWD/identity:/etc/fips" \
  fips-test:latest \
  keygen --dir /etc/fips
```

That key is then bind-mounted into `/etc/fips/fips.key`, so the sidecar keeps
the same FIPS identity even though `fips-on.sh` uses `docker compose up
--force-recreate`.

Delete `identity/fips.key` if you want the next `./fips-on.sh` run to create a
fresh sidecar identity.

## Why `sudo` Is Still Needed

Only `fips-host.sh` needs root, because macOS requires it for:

- `/etc/wireguard/fips0.conf`
- `/etc/resolver/fips`
- `wg-quick up/down`
- DNS cache flushes

Everything else runs as the normal user.

## Teardown

Run:

```bash
./fips-off.sh
```

This:

1. Calls `sudo ./fips-host.sh off` to remove the host WireGuard and DNS config.
2. Stops the Docker container.

## Generated Files

These are local runtime artifacts under `identity/` and should not be committed:

- `identity/fips.key`
- `identity/fips.pub`
- `identity/wireguard/client.key`
- `identity/wireguard/client.pub`
- `identity/wireguard/server.key`
- `identity/wireguard/server.pub`
- `identity/wireguard/wg0.conf`
