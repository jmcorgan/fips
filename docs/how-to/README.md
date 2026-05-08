# How-To Guides

Task-oriented, step-by-step recipes for operators with a specific
goal in mind. Each guide assumes the reader already knows what FIPS
is and wants to get a particular thing done — enable a feature,
deploy a component, troubleshoot a class of problem.

How-to guides do not teach concepts (that is the role of design/)
and do not enumerate options (that is the role of reference/). They
take the reader along the shortest correct path from "I want to do
X" to "X is done".

## Available Guides

| Guide | Goal |
| ----- | ---- |
| [enable-mesh-firewall.md](enable-mesh-firewall.md) | Activate the default-deny nftables baseline on `fips0` |
| [enable-nostr-discovery.md](enable-nostr-discovery.md) | Turn on Nostr-mediated discovery (3 capabilities — resolve, advertise, open — across 5 scenarios) |
| [deploy-tor-onion.md](deploy-tor-onion.md) | Run a Tor onion service for inbound FIPS connections |
| [tune-udp-buffers.md](tune-udp-buffers.md) | Set host sysctls so FIPS UDP sockets don't get clamped |
| [run-as-unprivileged-user.md](run-as-unprivileged-user.md) | Run the daemon under a dedicated unprivileged service account (drops the default-root posture) |
| [deploy-gateway.md](deploy-gateway.md) | Manually deploy `fips-gateway` on a non-OpenWrt Linux host (LAN-to-mesh outbound + mesh-to-LAN inbound port-forwards). For the OpenWrt path, see the gateway tutorial. |
| [troubleshoot-gateway.md](troubleshoot-gateway.md) | Diagnostic recipes for the gateway, organised by half (outbound, inbound, common) |
| [persistent-identity.md](persistent-identity.md) | Provision a stable Nostr keypair so the node keeps the same npub across restarts |
| [host-aliases.md](host-aliases.md) | Use shortnames (`test-us01.fips`, `my-laptop.fips`) instead of full npubs by editing `/etc/fips/hosts` or setting peer aliases |
| [set-up-bluetooth-peer.md](set-up-bluetooth-peer.md) | Configure a Bluetooth Low Energy peer link |
| [diagnose-mtu-issues.md](diagnose-mtu-issues.md) | Triage MTU-shaped failures and rule out their imposters (bufferbloat, transport saturation) |
