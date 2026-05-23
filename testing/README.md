# FIPS Testing

Integration and simulation test harnesses for FIPS, using Docker
containers running the full protocol stack.

## Test Harnesses

### [static/](static/) -- Static Docker Network

Fixed topologies with manual scripts for building, config generation,
connectivity tests (ping, iperf), and network impairment (netem).
Useful for deterministic debugging and validating specific topology
configurations.

| Topology    | Nodes | Transport | Description                      |
| ----------- | ----- | --------- | -------------------------------- |
| mesh        | 5     | UDP       | Sparse mesh, 6 links, multi-hop  |
| chain       | 5     | UDP       | Linear chain, max 4-hop paths    |
| mesh-public | 5+1   | UDP       | Mesh with external public node   |
| tcp-chain   | 3     | TCP       | Linear chain over TCP (port 8443) |
| rekey       | 5     | UDP       | Rekey integration test topology  |

### [tor/](tor/) -- Tor Transport Integration

End-to-end Tor transport testing with Docker containers running real
Tor daemons. Requires internet access for Tor bootstrapping.

| Scenario       | Description                                              |
| -------------- | -------------------------------------------------------- |
| socks5-outbound | Outbound SOCKS5 connections through Tor to clearnet peer |
| directory-mode  | Inbound via HiddenServiceDir onion service (co-located)  |

### [nat/](nat/) -- NAT Traversal Lab

Real Docker NAT traversal tests for the Nostr/STUN bootstrap path,
using router containers with `iptables`-based NAT, a local Nostr relay,
and a local STUN responder.

| Scenario  | Description                                                  |
| --------- | ------------------------------------------------------------ |
| cone      | Two NATed peers establish a UDP traversal path               |
| symmetric | UDP traversal fails under symmetric NAT, TCP fallback wins   |
| lan       | Peers on the same LAN prefer local addresses over reflexive  |

### [chaos/](chaos/) -- Stochastic Simulation

Automated network testing with configurable node counts, topology
algorithms (random geometric, Erdos-Renyi, chain, explicit), and fault
injection (netem mutation, link flaps, traffic generation, node
churn). 20 scenarios covering general stress testing, cost-based parent
selection, mixed link technologies (fiber/Bluetooth/WiFi),
transport-specific validation (UDP, TCP, Ethernet), and ECN/congestion
testing. Scenarios are
defined in YAML and executed via a Python harness that manages the full
lifecycle: topology generation, Docker orchestration, fault scheduling,
log collection, and analysis.

### [interop/](interop/) -- Mixed-Version Interop Harness

On-demand harness that runs an N-node full mesh from a node-spec where
each node can run a different build of the FIPS daemon, then attributes
every FMP/FSP/rekey/connectivity failure to a specific version pair
(same-version vs MIXED). Used to catch interop regressions between
builds, not as a per-commit CI gate; not part of `ci-local.sh`.

### [mesh-lab/](mesh-lab/) -- Mesh Reliability Lab

On-demand harness that runs a chosen integration suite N times under a
configurable host-pressure profile (idle / light / github-runner-
equivalent / heavy via `stress-ng`), per-container netem impairment,
and optional trace-level RUST_LOG, capturing per-rep diagnostics and a
mechanism-match summary across the run. Used for statistical reliability
characterization of known flake classes under calibrated stress, not as
a per-commit gate; not part of `ci-local.sh`.
