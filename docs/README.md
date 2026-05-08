# FIPS Documentation

FIPS (Free Internetworking Peering System) is a self-organizing
encrypted mesh network built on Nostr identities, capable of
operating over arbitrary transports — local networks, the public
internet, Tor, Bluetooth, or point-to-point links — without central
infrastructure.

With FIPS, your machine becomes a node in the mesh with a
self-generated cryptographic identity. There are two ways to
deploy it.

**As an overlay** on top of existing IP networks, FIPS lets
your node reach any other FIPS node wherever it sits — behind a NAT, on a
different ISP, on a phone over cellular, on a laptop with only
Bluetooth in range, or behind a Tor onion. The mesh forwards
IPv6 traffic transparently and end-to-end encrypted, with no
central VPN concentrator or coordinating server.

**From the ground up** over raw Ethernet, WiFi, or Bluetooth,
FIPS provides a complete permissionless network
without any pre-existing IP infrastructure, ISP, or DNS. Any
node that joins the link gets routable IPv6 addresses, peer
discovery, and a path to every other node automatically.

Either way, existing networking software runs over it unchanged:
SSH, HTTP servers, file transfer, anything IPv6-native works the
same way it would on a local network.

New to FIPS? Start with the [Getting Started](getting-started.md)
guide.

## Documentation Sections

### [Tutorials](tutorials/)

If you are starting from scratch and want a guided path to a
working mesh, go here.

### [How-To Guides](how-to/)

If you have a specific task in mind — enabling a feature,
deploying a component, diagnosing a problem — go here.

### [Reference](reference/)

If you need to look up wire formats, configuration keys, command
flags, or counter inventories, go here.

### [Design](design/)

If you want to understand how the mesh self-organizes, why FIPS
makes the choices it does, or how the pieces fit together, go
here.
