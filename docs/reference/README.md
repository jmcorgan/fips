# Reference

Information-oriented technical descriptions for lookup on demand.
Reference content describes *what is*: wire formats, configuration
keys, command-line flags, control-socket commands, default values,
file paths, exit codes. It is consulted, not read end-to-end.

Reference is austere by design: minimal narrative, no opinions, no
guidance on when to use a feature. The "why" lives in design/; the
"how do I accomplish X" lives in how-to/.

## Available Reference

| Document | Scope |
| -------- | ----- |
| [wire-formats.md](wire-formats.md) | All FMP and FSP message byte layouts, encapsulation walkthrough |
| [configuration.md](configuration.md) | Full YAML configuration reference for the daemon and gateway |
| [security.md](security.md) | nftables baseline, peer ACL, cryptographic primitives, rekey defaults, threat-resistance matrix |
| [nostr-events.md](nostr-events.md) | Kind 37195 advert, Kind 21059 traversal signaling, Kind 10050 inbox relays |
| [transports.md](transports.md) | Per-transport statistics counter inventory |
| [control-socket.md](control-socket.md) | Line-delimited JSON control protocol for the daemon and gateway |
| [cli-fips.md](cli-fips.md) | `fips` daemon CLI: options, exit codes, environment, files |
| [cli-fipsctl.md](cli-fipsctl.md) | `fipsctl` control-client: subcommands, options, exit codes |
| [cli-fipstop.md](cli-fipstop.md) | `fipstop` live-status TUI: tabs, keybindings |
| [cli-fips-gateway.md](cli-fips-gateway.md) | `fips-gateway` service CLI: options, exit codes, files |
