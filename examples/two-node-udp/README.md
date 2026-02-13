# Two-Node UDP Test

This example demonstrates two FIPS nodes communicating over UDP using Linux
network namespaces. Both nodes establish an encrypted peer link, build a
spanning tree, and create end-to-end sessions. With TUN and DNS enabled, you
can `ping6` between nodes using raw IPv6 addresses.

## Network Diagram

![Two-Node UDP](two-node-udp.svg)

## Prerequisites

- Linux with network namespace support (requires root for namespace setup)
- IPv6 enabled (`sysctl net.ipv6.conf.all.disable_ipv6` should be `0`)
- `iproute2` tools (`ip`), `dig` (from `dnsutils` or `bind-utils`)
- Rust toolchain (to build the FIPS binary)

## Node Identities

| Node | npub | FIPS Address |
|------|------|-------------|
| A | `npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m` | `fd69:e08d:65cc:3a6b:9c2c:2ac4:bd40:5e4b` |
| B | `npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le` | `fd8e:302c:287e:b48d:6268:122f:da76:b77` |

## Step 1: Build FIPS

From the FIPS source root:

```bash
cargo build
```

The binary will be at `target/debug/fips`. Note the absolute path — you'll
need it when running inside namespaces.

## Step 2: Create Network Namespaces

This creates two namespaces (`fips-a` and `fips-b`) connected by a virtual
ethernet pair. Each namespace has its own isolated network stack, including
its own routing table, TUN devices, and DNS resolver.

```bash
# Create namespaces
sudo ip netns add fips-a
sudo ip netns add fips-b

# Create a veth pair connecting them
sudo ip link add veth-a type veth peer name veth-b

# Move each end into its namespace
sudo ip link set veth-a netns fips-a
sudo ip link set veth-b netns fips-b

# Configure IPv4 addresses (used by UDP transport)
sudo ip netns exec fips-a ip addr add 10.0.0.1/24 dev veth-a
sudo ip netns exec fips-b ip addr add 10.0.0.2/24 dev veth-b

# Bring interfaces up
sudo ip netns exec fips-a ip link set veth-a up
sudo ip netns exec fips-b ip link set veth-b up

# Enable loopback in both (needed for DNS responder on 127.0.0.1)
sudo ip netns exec fips-a ip link set lo up
sudo ip netns exec fips-b ip link set lo up

# Enable IPv6 in both namespaces
sudo ip netns exec fips-a sysctl -w net.ipv6.conf.all.disable_ipv6=0
sudo ip netns exec fips-b sysctl -w net.ipv6.conf.all.disable_ipv6=0
```

Verify connectivity between namespaces:

```bash
sudo ip netns exec fips-a ping -c 1 10.0.0.2
```

## Step 3: Start Node A

Open **Terminal 1**. This runs the FIPS daemon for Node A inside its
namespace. The daemon creates a `fips0` TUN device, starts the DNS responder,
connects to Node B over UDP, and begins the Noise IK handshake.

```bash
sudo ip netns exec fips-a \
  env RUST_LOG=info \
  /path/to/target/debug/fips --config /path/to/examples/two-node-udp/fips-a.yaml
```

Replace `/path/to/` with the actual absolute paths to your build and this
example directory.

You should see output like:

```text
INFO fips: FIPS starting
INFO fips: Node created:
INFO fips:       npub: npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m
INFO fips:    address: fd69:e08d:65cc:3a6b:9c2c:2ac4:bd40:5e4b
INFO fips: TUN device active:
INFO fips:      name: fips0
INFO fips:   address: fd69:e08d:65cc:3a6b:9c2c:2ac4:bd40:5e4b
INFO fips: DNS responder started for .fips domain
INFO fips: Peer connection initiated (node-b)
```

## Step 4: Start Node B

Open **Terminal 2**. Run Node B in its namespace:

```bash
sudo ip netns exec fips-b \
  env RUST_LOG=info \
  /path/to/target/debug/fips --config /path/to/examples/two-node-udp/fips-b.yaml
```

Once both nodes are running, you should see handshake completion messages in
both terminals:

```text
INFO fips::node::handlers::handshake: Peer promoted to active
```

The spanning tree will converge within a few seconds (TreeAnnounce exchange),
followed by bloom filter exchange (FilterAnnounce).

## Step 5: Test DNS Resolution

The FIPS daemon includes a DNS responder that resolves `<npub>.fips` queries
to FIPS IPv6 addresses. Open **Terminal 3** to test it.

Query the DNS responder directly with `dig`:

```bash
# From Node A, resolve Node B's name
sudo ip netns exec fips-a dig @127.0.0.1 -p 5354 AAAA \
  npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le.fips

# Expected answer: fd8e:302c:287e:b48d:6268:122f:da76:b77
```

Watch Terminal 1 — you should see a log line (requires `RUST_LOG=debug`):

```text
DEBUG fips::dns: DNS resolved .fips name, registering identity
```

This confirms the identity cache was populated. The subsequent ping will be
able to route through the mesh.

> **Note:** `resolvectl` and system resolver integration (e.g., `ping6
> npub1...fips`) do not work inside network namespaces because
> `systemd-resolved` runs in the host namespace and is not accessible from
> within isolated namespaces. Use `dig @127.0.0.1 -p 5354` to query the
> DNS responder directly, and use raw IPv6 addresses for `ping6`. System
> resolver integration works when FIPS runs in the host namespace or with
> the future D-Bus auto-registration (Phase 2).

## Step 6: Ping Between Nodes

Now test end-to-end connectivity. The first ping triggers session
establishment (Noise IK handshake through the mesh), so it may take a moment
longer than subsequent pings.

### Ping Node B from Node A

From Terminal 3:

```bash
sudo ip netns exec fips-a ping6 -c 4 fd8e:302c:287e:b48d:6268:122f:da76:b77
```

### Ping Node A from Node B

```bash
sudo ip netns exec fips-b ping6 -c 4 fd69:e08d:65cc:3a6b:9c2c:2ac4:bd40:5e4b
```

Ping replies are handled by the kernel's IPv6 stack — when a ping arrives
at the destination's TUN device, the kernel sees it addressed to its own
`fips0` address and replies natively. FIPS handles the encrypted transport
between nodes; the kernel handles ICMPv6 Echo Reply.

## Step 7: Watch the Logs

While pinging, watch the daemon terminals for the protocol flow:

1. **DNS resolution** — `DNS resolved .fips name, registering identity`
2. **TUN packet** — `TUN packet received` with src/dst addresses
3. **Session initiation** — `Initiating session to <node_addr>`
4. **SessionSetup sent** — Noise IK msg1 sent through mesh
5. **SessionSetup received** — Responder processes msg1
6. **SessionAck** — Responder sends msg2 back
7. **Session established** — Both sides transition to Established
8. **DataPacket** — Encrypted IPv6 payload delivered

Set `RUST_LOG=debug` for the full protocol trace, or `RUST_LOG=info` for
high-level events only.

## Cleanup

Stop both FIPS daemons with Ctrl+C in Terminals 1 and 2. Then tear down
the namespaces:

```bash
sudo ip netns delete fips-a
sudo ip netns delete fips-b
```

This also removes the veth pair and TUN devices automatically.

## Troubleshooting

### "Permission denied" creating TUN device

The FIPS binary needs `CAP_NET_ADMIN` to create TUN devices. Running via
`sudo ip netns exec` already provides root privileges. If running outside
a namespace, use:

```bash
sudo setcap cap_net_admin+ep /path/to/target/debug/fips
```

### "Address already in use" on DNS port

Another process is using port 5354. Change the `dns.port` in the YAML config
to a different port (e.g., 5355).

### No handshake completion

Check that the veth pair is up and the namespaces can reach each other:

```bash
sudo ip netns exec fips-a ping -c 1 10.0.0.2
```

If this fails, the namespace setup is incomplete.

### IPv6 disabled

```bash
sudo ip netns exec fips-a sysctl net.ipv6.conf.all.disable_ipv6
# Should be 0
```

### DNS query returns no answer

Verify the DNS responder is running by querying it directly:

```bash
sudo ip netns exec fips-a dig @127.0.0.1 -p 5354 AAAA \
  npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le.fips
```

If `dig` works but `resolvectl query` or `ping6 <npub>.fips` doesn't,
this is expected — `systemd-resolved` runs in the host namespace and is
not accessible from inside network namespaces. Use raw IPv6 addresses
for testing within namespaces.
