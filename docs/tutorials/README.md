# Tutorials

If you have just installed FIPS, this is where to start. The
tutorials below take you from a freshly-installed daemon to a
node that:

- Has joined the public test mesh and can reach other nodes on it.
- Carries a stable identity that other operators can address.
- Discovers peers — and is discoverable — over Nostr.
- Hosts and consumes real services across the mesh.

Each tutorial is a complete, working session at the keyboard. You
configure something, restart the daemon, watch it come up, and
verify the result. The point is to build muscle memory, not to
cover every option.

> **Read them in order.** Each tutorial assumes the state the
> previous one left you in. If you skip ahead, the cross-references
> that lead you back may not match what you have on disk.

## The new-user progression

| # | Tutorial | What you'll do |
| - | -------- | -------------- |
| 1 | [join-the-test-mesh.md](join-the-test-mesh.md) | Add one public test peer to your config, watch the link come up, ping that peer and a second mesh node it routes you to. The starting point for everything else. |
| 2 | [persistent-identity.md](persistent-identity.md) | Pin your daemon to a stable Nostr keypair so your address stops changing on every restart. Other operators can now add you to their `peers:` lists; the services you host get a fixed name. |
| 3 | [resolve-peers-via-nostr.md](resolve-peers-via-nostr.md) | Stop hard-coding peer addresses. Drop the address line from your peer entry and let the daemon look up the current endpoint from public Nostr relays at dial time. |
| 4 | [advertise-your-node.md](advertise-your-node.md) | Publish your own UDP endpoint to Nostr so any operator who knows your npub can reach you, with a short final section on `udp:nat` best-effort hole-punching for nodes without a directly reachable UDP endpoint. |
| 5 | [open-discovery.md](open-discovery.md) | Switch to `policy: open` and let your peer list populate itself from the ambient `fips-overlay-v1` namespace. Hands-off mesh participation. |
| 6 | [reach-mesh-services.md](reach-mesh-services.md) | Drive ordinary IPv6 tools — `ping6`, `nc`, `traceroute6`, `curl`, `ssh` — at mesh nodes by `<npub>.fips`. Get a feel for the daemon's IPv6 adapter, which makes unmodified IPv6 software work over the mesh. |
| 7 | [host-a-service.md](host-a-service.md) | Bring up an HTTP server bound to `fips0` so mesh nodes can reach it, with a deliberate exposure decision (mesh-only vs every interface), and the mesh firewall as a default-deny baseline. The peer ACL (a separate, transport-layer control over which npubs may peer with your node) is briefly mentioned alongside. |
| 8 | [ground-up-mesh.md](ground-up-mesh.md) | Bring up a second deployment mode: two devices joined by Ethernet (or WiFi, or BLE) with no IP infrastructure between them. The mesh emerges from layer 2 up. Coexists with overlay peers — the same daemon can carry both. |

After tutorial 8 you have a fully participating mesh node that
reaches services hosted by other mesh nodes and hosts services of its own,
with identity, discovery, reachability, an explicit exposure
policy, and an understanding of both deployment modes — overlay
on top of existing IP, and ground-up where the mesh is the
network.

There is also a side trip you can take any time after tutorial 1:

- [ipv6-adapter-walkthrough.md](ipv6-adapter-walkthrough.md) —
  trace one `ssh` from DNS query through session setup to the
  far-side TUN, using `fipstop` and `fipsctl` to watch each step.
  Optional, but if you like seeing how the pieces fit together,
  this is the doc that shows you.

## Advanced

These are not part of the new-user progression. They assume you
have already worked through the tutorials above and now want to
fold FIPS into a wider network deployment.

- [deploy-fips-gateway.md](deploy-fips-gateway.md) — Stand up a
  `fips-gateway` on an OpenWrt access point so unmodified LAN
  hosts can reach `<npub>.fips` destinations through a DNS-
  allocated virtual IPv6 pool and kernel nftables NAT, with no
  per-host FIPS install. Also walks through one inbound port
  forward exposing a LAN service to mesh peers. Aimed at
  operators bridging a LAN segment into the overlay from the
  edge router. For a non-OpenWrt host the same deployment is
  in [../how-to/deploy-gateway.md](../how-to/deploy-gateway.md).

## When to use the how-to guides instead

The tutorials here walk through one specific path each. The
how-to guides under [../how-to/](../how-to/) are the operator
recipes — alternative provisioning paths, less-common
configurations, troubleshooting techniques. Once you have the
shape of FIPS in your head from these tutorials, the how-tos are
where you'll go to look up "how do I do X?" without being walked
through the surrounding context.
