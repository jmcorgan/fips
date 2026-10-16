# FIPS v0.5.3

**Released**: 2026-10-16

v0.5.3 is a maintenance release on the v0.5.x line. Most of it is security work: OpenWrt routers get default-deny firewall zones for FIPS and for the 802.11s mesh, the gateway translates only its LAN's traffic, the DNS responder stops answering forged or non-query traffic, and link handshakes, session setup and discovery no longer yield to forged or replayed messages. It also makes link rekeys recover from lost messages, fixes the gateway, transports and the Linux, OpenWrt, FreeBSD, macOS and Windows builds, and publishes the Rust package on crates.io as `fips-mesh`. There is no wire format change, so a mixed mesh works and nodes can be upgraded one at a time.

Read "Before you upgrade", below, if you run FIPS on OpenWrt, run the gateway, run FIPS on Windows, or have edited `/etc/fips/fips.nft`.

## At a glance

### Who should upgrade

- **Every node: upgrade.** The TLS library the Nostr relay connections use moves to a release that fixes four advisories, and every default build reaches it. On every platform, a captured link rekey message can no longer stop key rotation, a forged handshake reply can no longer end a dial, frames that fail to decrypt no longer remove a peer, a forged session setup can no longer hold back traffic to the node it names, and lookups, path-broken signals, Nostr adverts and LAN discovery adverts can no longer be used to redirect or starve discovery.
- **OpenWrt: upgrade, and read the OpenWrt notes below first.** On v0.5.2 `fips0` sat in the `lan` zone, so every FIPS peer could reach LuCI, SSH and DNS on the router, and the 802.11s mesh interfaces sat in no zone, so on OpenWrt 22.03 anyone in radio range could reach them over the mesh. The upgrade changes both, and it changes the mesh's basic rates, so routers you reach over the mesh must be upgraded in order.
- **Gateway operators: upgrade.** Hosts on any interface of a multi-homed gateway, including VPN interfaces, containers and virtual machines on the gateway host, could use its mappings and its mesh identity. A LAN host could hold the mapping limit with names it never used, and a restarted gateway could hand a cached address to a different name.
- **Linux: upgrade.** Besides the fixes every node gets, the `fips` and `fips-gateway` units now back off between restarts, a tarball upgrade no longer leaves `fips-dns` and `fips-gateway` stopped, and removing the `.deb` no longer leaves `.fips` lookups timing out.
- **Windows: upgrade, and read the Windows notes below.** The installer now stops instead of letting a service that ran from `\etc\fips` come up under a new identity with no warning.
- **macOS, FreeBSD and Android: upgrade for the fixes every node gets.** macOS also gets fixes for a daemon that stopped forwarding when one of its sending threads exited, FreeBSD for `.fips` names that did not resolve with pkg dnsmasq, and 32-bit Android builds again.

### Before you upgrade

- **OpenWrt: if you manage the router over FIPS, add a `src fips` rule for SSH, and for LuCI's ports if you use it, before upgrading.** `fips0` moves into its own `fips` zone, which rejects input, so router services are no longer reachable from FIPS peers unless a rule opens them. If fips-gateway serves a network in a zone other than `lan`, add a forwarding from that zone to `fips` too. See the [package README's Firewall section](https://github.com/jmcorgan/fips/blob/v0.5.3/packaging/openwrt-ipk/README.md#firewall).
- **OpenWrt with an 802.11s mesh: upgrade the routers you reach over the mesh one at a time, farthest first.** `fips-mesh-setup` now sets `basic_rate '6000 12000 24000'` on its mesh interfaces so 24.10 and 25.12 routers peer, and the upgrade sets it on existing ones. The new rates apply at the next network reload, which on a router with the gateway enabled happens during the upgrade. A reload can recreate the mesh interface, and a running `fips` does not form links over a recreated interface, so restart `fips` after that reload; see Upgrade notes. On 2.4 GHz a router on the new rates stops peering with one still on the old. OpenWrt 22.03 and 23.05 routers no longer peer on 2.4 GHz with upgraded 24.10 or later routers unless those routers set the old rates; see [Upgrading from 0.5.2 or earlier: the 802.11s mesh's basic rates](https://github.com/jmcorgan/fips/blob/v0.5.3/packaging/openwrt-ipk/README.md#upgrading-from-052-or-earlier-the-80211s-meshs-basic-rates).
- **Windows: the installer stops if `\etc\fips\fips.key` exists on the system drive and `C:\ProgramData\fips\fips.key` does not.** A service that an earlier release ran from `\etc\fips` reads only `C:\ProgramData\fips` after the installer runs, and came up with a new identity. If the key is this node's, move it to `C:\ProgramData\fips\fips.key`, carry the settings you need from `\etc\fips\fips.yaml` into `C:\ProgramData\fips\fips.yaml`, including `node.identity.persistent: true` (without it the service sets the key aside and starts under a new identity), and delete `\etc\fips\fips.yaml`. If you did not put the key there, delete it. Then run the installer again. If you registered the service yourself rather than with `install-service.ps1`, see the Windows upgrade notes first.
- **A config file that configures nothing now stops `fips` at start.** That is a file with no `node.identity.nsec`, `node.identity.persistent` off, no transports, no peers and, on Linux, no `gateway` section: an empty file, a comments-only one, or one that sets only settings such as `node.log_level`. Such a config started an ephemeral node with no transports. Finding no config file at all still starts on the defaults.
- **Gateway: only hosts on `gateway.lan_interface` are served after the upgrade.** Clients that reached the pool from another interface of the gateway host, such as VPN clients, or containers and virtual machines on the gateway host, lose `.fips` access, and no setting serves a second interface.
- **Gateway: a `gateway.lan_interface` that is a VLAN on a bridge stops serving clients whose traffic enters the bridge untagged** when `br_netfilter` passes bridged IPv6 to the firewall (`net.bridge.bridge-nf-call-ip6tables` at 1, its default once the module loads, or the bridge's own `nf_call_ip6tables` on), because the gateway now translates only traffic that arrives on `lan_interface`. The OpenWrt package sets `bridge-nf-call-ip6tables` to 0, so a stock OpenWrt router is not affected. A `gateway.pool` of `/128` now stops the gateway at start, and a pool with host bits set, such as `fd01::1/112`, is used as its prefix with a warning, which changes the addresses issued.
- **Linux mesh firewall: `/etc/fips/fips.nft` changed.** It now names the TUN in one place, `define fips_if = "fips0"`. If you edited the file, the `.deb` upgrade asks whether to keep yours, the AUR upgrade keeps yours and writes `fips.nft.pacnew`, and the systemd tarball keeps yours and writes `fips.nft.template`. A kept copy keeps the interface name it had. A host that renamed the TUN must police its `tun.name`, whether in the kept copy's `iifname` line or in the new file's `fips_if`, and reload `fips-firewall`. A `.deb` upgrade run without a terminal cannot ask about an edited file and stops with the services down; see the Debian upgrade notes. When the loaded firewall polices another interface than the node's TUN, the daemon now warns at start.
- **Debian and Ubuntu with a renamed TUN: run `systemctl mask fips-dns.service` before upgrading.** `fips-dns` looks only for `fips0`, so the upgrade otherwise ends with an error; see Known limitations.
- **Run without `--config`, `fips` and `fips-gateway` now apply every `node.*` setting from the config files on the search path.** Only `node.identity` and `node.leaf_only` were applied, so settings such as `node.log_level`, `node.limits` and `node.rekey` in those files were ignored. Check the files on the search path for values you did not mean to apply. Services started with `--config`, or on Windows with `FIPS_CONFIG` set, are not affected.
- No configuration key was added or removed, and no configuration key's default changed.

### What changed

- Security: OpenWrt firewall zones for `fips0` and the 802.11s mesh; gateway translation limited to its LAN; DNS replies only to queries, and never into the mesh for a forged mesh source; link rekey replays refused; forged handshake replies, session setups and SessionMsg3s no longer break handshakes; dials no longer held back by neighbours' unproven claims; lookup, `PathBroken`, Nostr advert cache, LAN discovery, coordinate cache and BLE hardening; key material cleared from memory; `rustls` 0.23.46.
- Links and sessions: a lost rekey reply is resent, link quality estimates no longer freeze after a rekey, same-epoch handshake messages are told apart as rekeys, replays and fresh dials, and a session that loses its route looks the destination up again.
- Gateway: firewall rebuilds retried, port forwards from mapped peers reach the LAN target from the gateway's LAN address, virtual IPs no longer reach the gateway host itself, and a stop during set-up is honoured.
- Packages: systemd restart backoff; OpenWrt services respawn without limit; dnsmasq restarted rather than reloaded; release-candidate packages sort below the release.
- Rust package: renamed `fips-mesh` and published on crates.io; the library is still `fips`.
- Deprecated: `node.rekey.enabled: false`, and on Windows the config search's `\etc\fips` probe.

## Security fixes

### OpenWrt: FIPS peers and the 802.11s mesh reached router services

On v0.5.2 the package put `fips0` in the `lan` zone and accepted all of its traffic, so every FIPS peer could reach the router's own services, such as LuCI, SSH and DNS. `fips0` now has its own default-deny zone, `fips`: FIPS peers reach the router only with replies to its own connections, ping and fips-gateway's port forwards, and port forwards can now be restricted with `src fips` rules. ICMPv6 from the WAN side is no longer forwarded into the mesh, and conntrack helpers are no longer assigned to traffic from FIPS peers.

`fips-mesh-setup` now also puts the 802.11s mesh interfaces it creates in a zone of their own, `fips_mesh`, which rejects all IP input and forwarding. The mesh is open at the radio layer and the interfaces were in no zone, so on OpenWrt 22.03, whose default input policy is ACCEPT, anyone in radio range could reach router services over the mesh. FIPS peers over the mesh use the Ethernet transport, which is not IP and is not affected. The upgrade moves `fips0` and adds existing mesh interfaces to the new zones; if the firewall reload or the save fails, the upgrade blocks new connections from FIPS peers, and IP traffic arriving on the mesh interfaces, until the firewall next reloads, and says why. The [package README](https://github.com/jmcorgan/fips/blob/v0.5.3/packaging/openwrt-ipk/README.md#upgrading-from-052-or-earlier-the-firewall) describes each case.

### Gateway: hosts off the LAN used the gateway's mappings

The gateway translates only traffic that arrives on its configured `gateway.lan_interface`. Traffic from its other interfaces to its virtual addresses is dropped, and traffic from them into the mesh is let through only when it is a reply; hosts on other interfaces of a multi-homed gateway, including VPN interfaces and containers or virtual machines on the gateway host, could use its mappings and its mesh identity. Two pool fixes go with it:

- A LAN host can no longer hold the mapping limit with names it never uses. A name that has never carried traffic expires after its TTL and grace period however often it is queried, and at the limit a new name replaces the oldest such mapping. Only a reply from the named node counts as traffic. The gateway warns at start when its pool is smaller than 2,200 addresses at the default TTL and grace period, which one LAN host naming new names can exhaust.
- After a restart, the gateway no longer gives an address the previous run handed out to a different name while clients may still have the old answer cached. Where `/var/run` is not on tmpfs, as in most containers, the gateway warns at each start that it cannot keep its pool state.

NAT table updates no longer pause `.fips` answering, refusals and NAT failures are logged once per episode, and `show_gateway` and `show_mappings` report the new counters. The gateway documentation no longer says the mesh firewall restricts port forwards, which it does not; the [deployment guide](https://github.com/jmcorgan/fips/blob/v0.5.3/docs/how-to/deploy-gateway.md#compose-with-the-mesh-firewall) gives a forward-chain recipe that does.

### DNS: replies to forged and non-query traffic

The `.fips` responder and the gateway's DNS forwarder no longer answer DNS responses or other datagrams that are not queries, which let one forged datagram start an endless exchange with another responder, and no longer copy records or extra questions from a query into the reply, which made a responder bound to a non-loopback address a reflector with up to about seven times amplification. A `.fips` query from a forged mesh source address sent to a non-loopback `dns.bind_addr` no longer gets its reply routed into the mesh: on Linux the reply leaves only by the interface the query arrived on, and on other platforms, and on Linux with a specific bind and no known mesh interface, it is sent only when the routing table takes it back out of the arrival interface. The [configuration reference](https://github.com/jmcorgan/fips/blob/v0.5.3/docs/reference/configuration.md) says which platforms keep mesh peers away from a wildcard `dns.bind_addr` and that such a bind answers every host on the node's other networks. The comment on `dns:` in the shipped `fips.yaml` was not changed and overstates the exposure that remains; the configuration reference is the current text.

### Link and session handshakes

- **A captured link rekey msg1 no longer stops key rotation.** A copy replayed after its rekey had completed was taken as a new request, and one replay per 120-second hold kept rotation stopped. The node now remembers the msg1s of the last 256 rekeys it answered for each peer and refuses a copy. A msg1 from an older rekey, or one captured before the peering last formed while the peer kept running, is not recognized; closing that needs a wire change.
- **A msg1 from an established peer is answered at the peer's established address**, not at the address it came from, so a copy of a peer's msg1 can no longer direct a msg2 at an address of the sender's choosing.
- **A forged or malformed handshake msg2 no longer ends an initial dial.** Anyone who saw the msg1 could end the dial, and every retry, with one datagram. A msg2 that does not authenticate is now discarded and the handshake state restored.
- **A forged session setup naming another node no longer holds back this node's traffic to that node**, and a node answers each session setup with one reply, so a forged setup draws one reply toward the address it names instead of five.
- **A replayed handshake message from a peer that is not linked no longer diverts its traffic**, and a single replayed message no longer blocks its real handshake for 15 seconds.
- Packets to a destination the mesh cannot reach now get an ICMPv6 Destination Unreachable instead of being held indefinitely, which let a gateway LAN host fill the table of held destinations.
- The Noise handshake's SHA-256 and HMAC states, the connection's handshake and session slots, and the handshake keypair are cleared when they are no longer needed. The [security reference](https://github.com/jmcorgan/fips/blob/v0.5.3/docs/reference/security.md) states what clearing key material in memory does and does not cover in a release build.

### Dials, discovery and neighbours

- **Neighbours can no longer hold back a node's dials with unproven claims.** BLE or Ethernet neighbours presenting links that claim a peer's key no longer stop the node dialling that peer, use up its per-peer path budget, or park its LAN candidate, and at `max_peers` such claims of a connected peer are held to four in flight per key, so a neighbour beaconing from fresh source MACs cannot fill every outbound handshake slot.
- **A single forged or reflected `PathBroken` signal no longer deletes coordinates a node verified by lookup.** A verified entry is demoted only when signals naming the destination arrive over two different links within 15 seconds. New counters appear in `show_routing`.
- **A peer that forwards a lookup can no longer stop the genuine answer by sending a forged one first**, and one peer repeating lookups for a target no longer stops other peers' lookups being forwarded.
- **A flood of Nostr adverts under new keys no longer evicts the adverts of configured or linked peers**, an honest author that misses one republish keeps its slot for one republish interval, and a peer configured with an upper-case npub now finds its advert.
- **LAN (mDNS) discovery** dials an advertised address only on the link the advert arrived on, paces its dials, refuses an advert whose host label belongs to a known peer under another npub, and no longer crashes on a malformed npub with debug logging on.
- A traversal offer can make the node probe a private IPv4 address only within one of its own interface prefixes, a datagram from another address can no longer stop a Nostr-discovered peer being retried for a day, the lookup failure table is bounded, and the coordinate cache is bounded by the coordinates it stores and charges each link peer for the space its hints take.
- An inbound TCP or Tor onion connection that goes about 64 seconds (at default settings) without a complete frame is dropped, and BLE links carrying an established session are no longer displaced by new BLE connections.

### rustls advisories

The lockfile moves `rustls` from 0.23.45 to 0.23.46 for RUSTSEC-2026-0346 (`Debug` output of client session values exposed TLS secrets), RUSTSEC-2026-0347 (buffered application data sent to the outer server after an ECH rejection), RUSTSEC-2026-0348 (Brotli certificate decompression could allocate up to 1 GiB before authentication) and RUSTSEC-2026-0349 (an unauthenticated ServerHello could downgrade later connections to classical key exchange). It is the TLS client the Nostr relay connections use. The update is within the version range the dependencies already allowed. Whether each advisory is reachable through FIPS's use of the client was not assessed.

## Notable fixes to bugs in v0.5.2

- **A link rekey whose msg2 is lost now completes on the initiator's next msg1 resend**, instead of the link going without rekeying until the responder's 120-second hold expired. The wire format is unchanged.
- **Link quality estimates no longer freeze after a rekey.** Frames sent on the old session just before the switch were counted into the new session's state, so loss and round-trip estimates, and the link costs and parent selection built on them, could stay stale for most of a rekey interval.
- **Twenty frames that fail to decrypt no longer remove the peer.** The index travels in clear, so anyone who had seen one frame of a link could tear it down from any address. Such frames are now dropped and one warning is logged; a real key mismatch still ends at the link-dead timeout.
- **A stop sent while `fips` or `fips-gateway` is starting is no longer lost.** As a container's PID 1, `fips` ignored it until the container's stop timeout killed it with no drain. The example compose files now run their containers under an init.
- **Run without `--config`, the daemon applies every `node.*` setting from the search path**, as described under "Before you upgrade".
- **A systemd tarball upgrade restarts `fips-dns` and `fips-gateway`** when they were running, instead of leaving `.fips` resolution and the gateway down.
- **Removing the `.deb` without purging removes the `.fips` DNS routing** when `fips-dns` was not running, as purging already did.
- **TCP tries a hostname's remaining addresses** after a connection fails, and **a UDP peer configured by hostname no longer holds up the node** while the system resolver is slow or down.
- **The receive loop no longer dials when it answers a handshake** on a TCP, Tor or Nym connection that has closed, which stalled it for the whole connect timeout per send and dropped other peers' links ([#176](https://github.com/jmcorgan/fips/issues/176)). Transport counters now report as they stand, and count connected UDP traffic and background connect failures.
- **macOS**: an encrypt worker or ordered-sender thread that exits no longer stops forwarding.
- **Windows**: an ICMP port-unreachable for one UDP peer no longer shows up as a receive error on the socket every UDP peer shares.
- **OpenWrt 24.10 and 25.12 routers set up with `fips-mesh-setup` now peer** over 802.11s, as described under "Before you upgrade".

## OpenWrt

Besides the zones and the basic rates above:

- **The `fips` and `fips-gateway` services respawn without limit**, 5 seconds after each exit. procd gave up for good after six quick exits, so a router whose daemon hit a run of failures, such as a missing interface at boot, stayed off the mesh until someone restarted it.
- **dnsmasq forwards `.fips` to fips-gateway only while the gateway is listening**, and back to the daemon whenever the gateway exits. A gateway that failed to start left LAN clients' `.fips` lookups going to a port nothing held.
- **The gateway keeps the LAN's global-scope address, `2001:2:f1b5::1/64`, across stops and restarts**, and deletes it only when the gateway is turned off. Setting and deleting it on every start and stop reloaded the network each time, which on OpenWrt 25.12 recreates `br-lan` and drops the LAN for a few seconds.
- The shipped config and README agree that the LAN Ethernet transport binds `br-lan`. If you changed the `lan` entry in `/etc/fips/fips.yaml` to a member port such as `lan1` or `eth1`, change it back; your edited config is kept across upgrades, so the upgrade will not correct it.
- A package built from the SDK feed `Makefile` now carries the released packages' maintainer scripts, and `build-ipk.sh` and `build-apk.sh` find the binaries wherever cargo put them.
- Release-candidate `.ipk` packages are versioned `vX.Y.Z~rcN`, so a router that ran a candidate is upgraded by the release, and development builds are no longer uploaded to Blossom or announced as NIP-94 events: only release tags publish there.

## Gateway

- Failed firewall rebuilds are retried every ten seconds without waiting for another mapping change.
- A port-forwarded connection from a peer that also has a live `.fips` mapping now reaches the LAN target from the gateway's LAN address, as every other peer's does.
- Connections the gateway host makes to a mapped virtual IP reach the mapped node, where they reached the gateway itself, and connections to a virtual IP with no mapping are refused, where a stale DNS answer could open a session on the router.
- The relayed NXDOMAIN carries an SOA, so resolvers cache it for up to `gateway.dns.ttl`, and TTLs above 2147483647 are clamped to it.

## Linux, FreeBSD, Windows and Android

- **The `fips` and `fips-gateway` systemd units back off between automatic restarts**, 5 s, 7 s, 10 s, 15 s, 21 s and then 30 s, instead of restarting every 5 s for as long as the start fails. They still never give up. systemd older than v254 keeps the fixed 5 s delay.
- **Standalone dnsmasq is restarted, not reloaded**, by `fips-dns-setup` on Linux and by the DNS scripts with pkg dnsmasq on FreeBSD, so `.fips` names resolve without a manual restart and are dropped on teardown.
- When no supported DNS resolver is found, `fips-dns-setup` no longer tells the host to run `apt install`; it names systemd-resolved and how to start it.
- A release-candidate `.deb` is versioned `X.Y.Z~rcN`, so the release upgrades a host that installed a candidate.
- The Ethernet transport no longer leaks a socket when its interface is missing, UDP receive errors back off instead of spinning, and an Ethernet peer's address is always shown as a MAC.
- Windows: the ZIP's `README.txt` lists `\etc\fips\fips.yaml` among the files a foreground run reads and says to stop the service before rerunning the installer, and the daemon warns about a `fips.yaml` or `fips.key` in `\etc\fips` that the run does not use.
- fips builds for 32-bit Android (`armeabi-v7a` and `x86`) again.

## Rust package: `fips-mesh`

The Rust package is now named `fips-mesh` and is published on crates.io under that name, since `fips` there belongs to another project. The library is still `fips`, and the binaries, the Debian package and every other package keep their names. `cargo` commands that name the package change from `-p fips` to `-p fips-mesh`. A crate that depends on FIPS adds `package = "fips-mesh"` and keeps the key `fips`, so `use fips::...` is unchanged:

```toml
[dependencies]
fips = { package = "fips-mesh", version = "0.5.3" }
```

The git dependency in the [native datagram API how-to](https://github.com/jmcorgan/fips/blob/v0.5.3/docs/how-to/use-the-native-datagram-api.md) pins `tag = "v0.5.3"`, so it builds this release rather than the default branch, which is the next release in development. The published crate does not carry the examples, the `docs/` tree or the test harnesses; the two native API examples build from a checkout. `cargo install fips-mesh` installs the four binaries but is not an install path: the daemon also needs its service units, a config, the `fips` group and the DNS setup, which the packages provide.

## Compatibility

v0.5.3 is wire-compatible with v0.5.2 for every encoding defined in the files that define FIPS's frames and messages: the seven `src/proto/*/wire.rs` files and their tests, `src/proto/codec.rs`, `src/identity/encoding.rs`, `src/native/client/codec.rs`, `src/noise/`, and the two wire-format reference documents. The diff over them since v0.5.2 is not empty, and none of it changes an encoding: one accessor over existing bytes of a lookup response, a rollback wrapper around an unchanged msg3 reader, two helpers that clear memory, comments and tests. That diff does not cover encoders and parsers elsewhere: the FMP and FSP state machines, the handshake and session handlers, transport framing, mDNS records, Nostr event content, the native API's daemon side and the control socket. The mDNS service type and TXT keys and the Nostr advert and signal event kinds are unchanged. Behavioural compatibility with older nodes rests on the mixed-version interop run described below.

Several changes alter what a node does with messages an older peer sends, not what it sends:

- **Against a v0.5.2 or older peer, recovery from a genuine key desynchronisation now takes the link-dead timeout** (30 seconds by default) rather than twenty frames, since frames that fail to decrypt no longer remove the peer. The node logs one `Excessive decryption failures` warning when the old threshold is reached and keeps the peer.
- A v0.5.3 node now answers a resent rekey msg1 with the msg2 it stored, refuses a replayed one, and answers a peer's rekey within 30 seconds of the previous one once 10 seconds have passed; an older node on the other end of the link keeps its own behaviour.
- **While older nodes remain, a lost rekey reply costs them more than it costs a v0.5.3 pair.** In the mixed-version interop run, when a v0.5.1 node's rekey reply was lost, the link dropped for about a minute (the link-dead timeout, then a reconnect); when a v0.5.2 node's reply was lost, rekeying on that link stalled for up to 120 seconds, logging `FMP rekey aborted` at debug level, without losing the link. Both go away as those nodes upgrade.

No configuration key was added or removed, and no default changed.

## Known limitations

- **The coordinate hint budget** (1,024 weight a second per link peer, burst 4,096) is not established against a measured honest rate. If `coord_hint_unfunded` in `fipsctl show routing` is not zero on your node, please report it.
- **Replayed link-setup msg1s are bounded, not stopped**: a node remembers up to eight per peer per 15 seconds, and a replayed rekey msg1 from an older rekey is not recognized. Closing either needs a wire change.
- **A node still relays every distinct lookup response for a request it forwarded**, so forged responses cost relay traffic, though the forged answer no longer wins.
- **A genuine BLE announcement behind 16 candidates in one poll is still discarded.** BLE is tested with mock I/O only.
- **On Linux, an Ethernet transport does not form links over an interface that is recreated under it** until `fips` restarts. On OpenWrt, a `wifi reload`, a LuCI apply or turning the gateway off can recreate the mesh or LAN interface; restart `fips` after any of them. This is not new in v0.5.3.
- **On Debian and Ubuntu, `fips-dns` does not work on a host that renamed the TUN.** It looks only for `fips0`, so it fails to start, and a `.deb` upgrade then ends with an error and leaves the package half-configured, though the daemon runs on the new binary. Run `systemctl mask fips-dns.service` before upgrading; disabling it is not enough, because the upgrade enables it again. This is not new in v0.5.3.
- **Port forwards are not firewall-gated on Linux by default.** Every mesh node that can reach the gateway can reach every configured port forward unless the [documented recipe](https://github.com/jmcorgan/fips/blob/v0.5.3/docs/how-to/deploy-gateway.md#compose-with-the-mesh-firewall) is applied.

## Deprecated

- **`node.rekey.enabled: false`.** The disabled path is less tested and not supported, and the option is removed in v2. It still works as before. Leave rekey on; nothing replaces the setting.
- **Windows: the config search's probe of `\etc\fips\fips.yaml` on the current drive.** Any local user can create that file. The daemon warns when it loads a config from there, and from v0.6.0 the search no longer looks there. Move the settings you need into `C:\ProgramData\fips\fips.yaml`.

## Upgrade notes

**OpenWrt.** Before upgrading, add the SSH rule and any gateway forwarding described under "Before you upgrade", and plan the order of an 802.11s mesh's routers. Copy the package to `/tmp` on the router. On OpenWrt 25 and later run `apk add --allow-untrusted /tmp/fips_<new-version>_<arch>.apk`; on 24.10 and earlier run `opkg install /tmp/fips_<new-version>_<arch>.ipk`, with the file name you downloaded in place of the placeholders. When you reach routers over the mesh, upgrade them one at a time, farthest first. The rate change takes effect at a network reload, which can recreate the mesh interfaces, and a running `fips` does not form links over a recreated interface, so restart it after the reload. Over SSH, run the three steps as one detached command, since the session can drop part-way: `sh -c 'trap "" HUP; opkg install /tmp/fips_<new-version>_<arch>.ipk; wifi reload; sleep 15; service fips restart' </dev/null >/tmp/fips-upgrade.log 2>&1 &`, with the `apk add` command in place of `opkg install` on OpenWrt 25 and later. The command ignores the hangup itself because OpenWrt's BusyBox does not always include `nohup` or `setsid`; its output is in `/tmp/fips-upgrade.log`. On a router with the gateway enabled, the first upgrade from 0.5.2 deletes and re-adds the LAN's global-scope address, reloading the network each time, which on OpenWrt 25.12 recreates `br-lan` and can drop the LAN twice for a few seconds. The LAN's Ethernet transport is expected not to form links over the recreated `br-lan` either (the same fault, reproduced on a recreated test interface but not yet on a router), so restart `fips` after the upgrade on such a router too; the restart in the command above covers it. An edited `/etc/fips/fips.yaml` is kept.

**Debian and Ubuntu.** `apt install ./fips_0.5.3_<arch>.deb`, with `amd64` or `arm64` in place of `<arch>`. If you edited `/etc/fips/fips.nft`, dpkg asks whether to keep your version. The default, N, keeps it, and a copy you already edited for a renamed TUN keeps working. Y installs the new file and the upgrade loads it at once, so on a host that renamed the TUN it then polices `fips0`: set `define fips_if` to your `tun.name` in the new file and run `systemctl reload fips-firewall`. An upgrade run without a terminal, such as from a script or a configuration management tool, cannot ask: it stops at the prompt with the services stopped and the package not configured. Pass `-o Dpkg::Options::=--force-confold` (keep yours) or `-o Dpkg::Options::=--force-confnew` (take the new one) to `apt`, or `--force-confold` or `--force-confnew` to `dpkg`. On a host that renamed the TUN, run `systemctl mask fips-dns.service` first (see Known limitations). `/etc/fips/fips.yaml` is not a dpkg conffile and is left as it is. The upgrade restarts the services as v0.5.2's did.

**Arch Linux.** pacman does not restart services: after the AUR package updates, run `systemctl restart fips.service`, and `systemctl restart fips-gateway.service` if you run the gateway. An edited `fips.yaml` or `fips.nft` is kept and the new one is written beside it as `.pacnew`; the new `fips.yaml` differs in comments only. After merging `fips.nft.pacnew`, set `fips_if` to your `tun.name` if you renamed the TUN, and run `systemctl reload fips-firewall` if it is active.

**systemd tarball.** `install.sh` keeps an existing `/etc/fips/fips.yaml` and `/etc/fips/fips.nft` and writes the new versions beside them as `fips.yaml.template` and `fips.nft.template`. Your `fips.nft` keeps the interface name it had; if it does not name your `tun.name`, change its `iifname` line to that name, or take `fips.nft.template` and set its `fips_if`. The upgrade now restarts `fips-dns` and `fips-gateway` if they were running. Run `systemctl reload fips-firewall` afterwards if the firewall is active.

**Windows.** Open an elevated PowerShell in the folder where you unzipped the new ZIP, stop the service (`Stop-Service fips`), run `powershell -ExecutionPolicy Bypass -File .\install-service.ps1`, and start the service (`Start-Service fips`). If you registered the service yourself, with `fips.exe --install-service` rather than with `install-service.ps1`, run `sc.exe qc fips` first: if its `BINARY_PATH_NAME` does not name `C:\Program Files\fips\fips.exe`, run your old `fips.exe --uninstall-service` before the installer, because the installer does not repoint a service that already exists, and the service would keep starting the old binary. If the installer stops because `\etc\fips\fips.key` exists and `C:\ProgramData\fips\fips.key` does not, and the key is this node's, move it to `C:\ProgramData\fips\fips.key`, carry the settings you need from `\etc\fips\fips.yaml` into `C:\ProgramData\fips\fips.yaml`, including `node.identity.persistent: true` (without it the service sets the key aside and starts under a new identity), and delete `\etc\fips\fips.yaml`. If you did not put the key there, delete it. Then run the installer again.

**FreeBSD.** Install the new package with `pkg install ./fips-0.5.3-freebsd-amd64.pkg`, then run `service fips restart` and, if you use it, `service fips_dns restart`, and check `fipsctl show status`. The restart is required: the package starts the new daemon itself, but pkg 2.8.4 ends it when pkg exits, so without the restart `fips` is left stopped. `pkg add` over an installed package does not take the upgrade path: it reinstalls and leaves the old daemon running on the replaced binary.

**Gateway.** If `gateway.lan_interface` is a VLAN device on a bridge, such as `br-lan.1` under bridge VLAN filtering, check bridge netfilter before upgrading: when `br_netfilter` is loaded and `net.bridge.bridge-nf-call-ip6tables` is 1, or the bridge has `nf_call_ip6tables` on (`ip -d link show` on the bridge), the gateway no longer serves clients whose traffic enters the bridge untagged, and setting `net.bridge.bridge-nf-pass-vlan-input-dev` to 1 does not change that. Setting `net.bridge.bridge-nf-call-ip6tables=0` and turning the bridge's `nf_call_ip6tables` off restores them, but bridged IPv6 traffic on that host then bypasses the IPv6 firewall, so do this only if nothing relies on it; otherwise do not upgrade that gateway yet. The OpenWrt package already sets `bridge-nf-call-ip6tables` to 0 (see the LAN trust boundary in the [gateway design document](https://github.com/jmcorgan/fips/blob/v0.5.3/docs/design/fips-gateway.md)). A `gateway.pool` of `/128` must be widened before the upgrade, or the gateway stops at start. After the upgrade only hosts on `gateway.lan_interface` are served: VPN clients, and containers and virtual machines on the gateway host, that reached the pool from another interface lose `.fips` access.

**Rolling upgrade.** No coordination is needed beyond the OpenWrt mesh order above. Upgrade nodes in any order; links to v0.5.1 and v0.5.2 nodes can drop or stall briefly while those nodes remain, as described under Compatibility.

## Dependencies

`cargo audit` reports no vulnerability in the release's lockfile. It allows five advisories, each accepted for this release, and one yanked crate:

- RUSTSEC-2024-0384, `instant` (unmaintained), through `nostr`.
- RUSTSEC-2026-0243, `nostr-relay-pool` (unmaintained), through `nostr-sdk`.
- RUSTSEC-2024-0436, `paste` (unmaintained), through `netlink-packet-core` on Linux.
- RUSTSEC-2024-0449, `unsafe-libyaml` (unmaintained), through `serde_yaml`, the config file parser. It is new to the advisory database since v0.5.2, not to the lockfile. Replacing the parser changes how every `fips.yaml` is parsed, so it is left for a later release.
- RUSTSEC-2026-0253, `lru` (unsound), through `nostr-database` and `nostr-relay-pool`.
- `negentropy` 0.5.1 (yanked), through `nostr-relay-pool`.

No crate was added to `Cargo.lock`: it lists 449 packages at v0.5.2 and at this release. `if-addrs` 0.15, `hmac` 0.13 and `windows-sys` 0.61 became direct dependencies, but all three were already in the lockfile as transitive ones, and `sha2` and `hmac` now enable `zeroize`.

## What was measured and what was not

**Measured, at the release's source content** (the same source as the tag, with the version string at `0.5.3-dev`):

- The full local test run, all 47 of its suites and checks, including the chaos scenarios, the NAT traversal, gateway, firewall, DNS resolver and mDNS suites, the OpenWrt maintainer-script scenarios, and the `.deb` install suite on five distributions, at the release's source.
- GitHub CI and the Linux, macOS, Windows, FreeBSD and OpenWrt package workflows, run on the release's source: all succeeded.
- The library's 3,361 unit tests, run again from the unpacked crate that `cargo publish --dry-run` builds.
- `cargo audit`: no vulnerability, with the five allowed advisories and one yanked crate listed above.
- The 100-node discovery test.
- Library test coverage, measured with `cargo llvm-cov --lib`: 86.85% of lines at this release, against 82.35% at v0.5.2 by the same command.
- The mixed-version interop run against v0.5.2 and v0.5.1 nodes, with and without 10 ms of delay and 2% loss, and in two-node runs against v0.5.2 at 8% and 15% loss. No link was lost with a v0.5.3 or v0.5.2 node answering a rekey, and session setup and rekey against v0.5.2 completed in both directions with a message lost on the path. Two runs went red, each explained by the older node: two links to a v0.5.1 node dropped when its rekey reply was lost, the defect v0.5.2 fixed, and one run at 15% loss missed the test's first-rekey window because a v0.5.2 node held its rekey for 120 seconds after its reply was lost.
- The FreeBSD package upgrade from v0.5.2 on FreeBSD 15.1 with pkg 2.8.4, with the package built by the release workflow: the new binary is installed and the config, key and identity kept. The package's own restart did not last, and the upgrade passed with the restart the upgrade notes require. `pkg add` over an installed package was measured to reinstall rather than upgrade.
- The `.deb` upgrade from the published v0.5.2 package on Debian 12 amd64, with an edited `fips.nft` under both answers to dpkg's prompt, without a terminal, and with a renamed TUN, using a package built from the release's packaging files.
- The Debian package built through the release's container script, with all four binaries at a glibc floor of 2.34 against the 2.35 the package declares, installed on Debian 12 and 13 and Ubuntu 22.04, 24.04 and 26.04, with the upgrade path exercised on Debian 12 against a repacked copy of the same package.
- The OpenWrt `.ipk` cross-compiled for aarch64 and x86_64, and its contents listed. The `.apk` cannot be built on the build host used here and is built by the release workflow.
- The release candidate's Windows ZIP on GitHub-hosted Windows runners, under Windows PowerShell 5.1 and PowerShell 7: a fresh install, an upgrade from an installer-made v0.5.2 service with its address kept, the refusal when only `\etc\fips\fips.key` exists, the warning when the config is loaded from `\etc\fips`, and the key move for a service registered by hand, following the upgrade notes, with the node's identity kept.
- A compile check for macOS, Windows and FreeBSD targets from Linux.
- The wire format, by the diff described under Compatibility.

**Not measured when this was written:**

- No published v0.5.3 artifact existed. The checks above ran against artifacts built by the same scripts and workflows the release uses.
- Recovery from a key desynchronisation against a v0.5.2 peer: no way to cause one in the test harness was available.
- No field soak was run. Not exercised on live nodes under real mixed-version traffic: link rekey msg1 replay refusal and same-epoch msg1 handling, the msg2 resend, session setup without the responder's SessionAck resend, recovery from a key desynchronisation against a v0.5.2 peer, and the handshake changes in the security fixes (a msg2 that fails to authenticate discarded and the handshake restored, and the handling of replayed msg1s for peerings not yet heard from).
- The OpenWrt upgrades on router hardware: no upgrade from v0.5.2 was run on a router, on OpenWrt 25.12 or any other release. The firewall zone move, the basic rates and the LAN prefix change are tested in CI in a BusyBox container against stubs and rootfs images, not under a real opkg or apk upgrade.
- BLE, which is tested with mock I/O only, and macOS and Android, which were not run on hardware.
- The `.deb` upgrade from v0.5.2 on Ubuntu or arm64, and the AUR upgrade on an Arch host.
- Reproducibility across machines, which has never been tested. The tarball builds byte-identically twice on one machine.

## Getting v0.5.3

- **Linux x86_64 / aarch64**: `.deb` and tarball at the [v0.5.3 release page](https://github.com/jmcorgan/fips/releases/tag/v0.5.3).
- **Arch Linux**: `fips` from the AUR, once every package workflow for the release has finished.
- **macOS**: `.pkg` at the v0.5.3 release page.
- **Windows**: ZIP at the v0.5.3 release page.
- **FreeBSD (x86_64)**: `.pkg` at the v0.5.3 release page.
- **OpenWrt**: `.ipk` (OpenWrt 24.x and earlier) or `.apk` (OpenWrt 25+) at the v0.5.3 release page, for `aarch64_cortex-a53` and `x86_64`.
- **Rust crate**: [`fips-mesh`](https://crates.io/crates/fips-mesh) 0.5.3 on crates.io, for embedding the library.
- **From source**: `cargo build --release` from a checkout of the v0.5.3 tag (Rust 1.94.1 per `rust-toolchain.toml`; `libclang-dev` is a required Linux build prerequisite, and on glibc Linux so are `libdbus-1-dev` and `pkg-config`).
- **Nix / NixOS**: `nix build .#fips` from a checkout of the v0.5.3 tag (see the Nix section of [`packaging/README.md`](https://github.com/jmcorgan/fips/blob/v0.5.3/packaging/README.md)). To run v0.5.3 from the NixOS module, set `inputs.fips.url = "github:jmcorgan/fips/v0.5.3"`, then run `nix flake update fips` and `nixos-rebuild switch`.

There is no Android daemon artifact. Android is supported as an embedded crate.

The full changelog lives in [`CHANGELOG.md`](https://github.com/jmcorgan/fips/blob/v0.5.3/CHANGELOG.md). The release has 197 commits since v0.5.2 (`git rev-list --count --no-merges v0.5.2..v0.5.3`): 194 of source content, two for these notes, and the version change. Issues and discussion at [github.com/jmcorgan/fips](https://github.com/jmcorgan/fips). Security reports have a private channel; see [`SECURITY.md`](https://github.com/jmcorgan/fips/blob/v0.5.3/SECURITY.md).

## Contributors

Thanks to everyone who contributed code, packaging work, bug reports, or reviews to this release.

- [@jmcorgan](https://github.com/jmcorgan) (Johnathan Corgan): release shepherd; the security fixes, link rekey fixes, gateway, packaging and transport fixes, and the `fips-mesh` rename.
- [@Origami74](https://github.com/Origami74) (Arjen): reported the receive-loop stall on TCP connect-on-send ([#176](https://github.com/jmcorgan/fips/issues/176)); fixed a crossed BLE handshake that closed the shared link ([#179](https://github.com/jmcorgan/fips/pull/179), landed as `c96e43da`), a session that went dark after losing its route ([#185](https://github.com/jmcorgan/fips/pull/185), `8b55b7fe`) and the 32-bit Android build ([#191](https://github.com/jmcorgan/fips/pull/191), `7ee01548`); made `fips` refuse a config that configures nothing ([#186](https://github.com/jmcorgan/fips/pull/186), `fb32bf87`), the OpenWrt services respawn without limit ([#188](https://github.com/jmcorgan/fips/pull/188), `f18d7903`) and the systemd units back off between restarts ([#190](https://github.com/jmcorgan/fips/pull/190), `245b3d5f`); wrote the reachability how-to ([#189](https://github.com/jmcorgan/fips/pull/189), `42ac4bd6`); and fixed clippy on macOS for Linux-only test helpers (`83ea6e7c`).
- [@mmalmi](https://github.com/mmalmi) (Martti Malmi): the Ethernet socket leak ([#171](https://github.com/jmcorgan/fips/pull/171), landed as `968d75da`), TCP trying a hostname's remaining addresses ([#172](https://github.com/jmcorgan/fips/pull/172), `712faebd`), UDP receive-error back-off ([#174](https://github.com/jmcorgan/fips/pull/174), `f6ab5d5c`) and the gateway's firewall rebuild retry ([#175](https://github.com/jmcorgan/fips/pull/175), `f1997d7f`).
- [@btcforplebs](https://github.com/btcforplebs) (Logen): reported that a Nostr traversal connect could stall for `signal_ttl_secs` when both peers dialled and one offer was lost ([#181](https://github.com/jmcorgan/fips/issues/181)), and fixed it ([#183](https://github.com/jmcorgan/fips/pull/183), landed as `d7947108`).

<!-- markdownlint-disable-file MD013 -->
