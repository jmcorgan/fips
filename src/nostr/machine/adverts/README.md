# src/nostr/machine/adverts

The overlay advert, with no Nostr types: what an advert may name, the checks
a peer's advert must pass, when it stops being valid, which peers' adverts
the node holds, how its own advert is assembled from its transports, and
which advert of its own it publishes. The shell reads
the Nostr event (its `protocol` tag, its JSON content, its `created_at` and
NIP-40 expiration, and whether it has expired) and passes the body and the
numbers in; it signs and sends the advert this directory tells it to
publish.

## Files

- `mod.rs`:
  - the endpoint rule: `endpoint_advert_is_publicly_usable` keeps `udp:nat`,
    a Tor endpoint naming a version 3 onion with a port (56 base32
    characters and `.onion`, checked for syntax only, so no IP address or
    DNS name for Tor), and a UDP or TCP address with a nonzero port whose host is
    not one `is_unroutable_direct_advert_ip` refuses (the never-punchable,
    private and documentation ranges of `punch/plan.rs`, and the advert's
    own reserved term, `is_reserved_ip`: `0.0.0.0/8`, `240.0.0.0/4` and
    `2001:db8::/32`, which the punch planner does not use; `198.18.0.0/15`
    is left out, since the NAT lab uses it as its public internet). An IP
    literal is judged by the address it names, so an IPv4-mapped IPv6
    address is judged as its IPv4 address, and an IPv6 address with a zone
    index is refused, since the zone names one of the receiver's
    interfaces. An
    endpoint that is not a socket address as written goes to `dial_host`:
    a bracketed host must be an IPv6 address and a canonical dotted quad an
    IPv4 one, each judged as a literal; anything else must be a host name
    of ASCII letters, digits, `-` and `_` in labels of up to 63 bytes, 253
    in all, one trailing dot allowed, not under `localhost`, and not ending
    in a numeric label, since such a host is an IPv4 address in another
    spelling (`127.1`, `0x7f000001`). A host name is not resolved here, so
    one that resolves to a private address is still accepted. The same
    rule trims our own advert before it is published (`publisher.rs`).
    Where it is stricter than FRC-1601 Appendix C.8, the tests say so row by
    row;
  - `apply_nat_rule`, the rule for a `udp:nat` endpoint, written once for
    publishing and validation: an advert with one must name signal relays
    and STUN servers, and one without carries neither. It returns which is
    missing and each caller words the refusal, since the two have always
    used different text;
  - `validate_overlay_advert`, the checks on a peer's advert body
    (identifier, version, at least one publicly usable endpoint, the
    `udp:nat` rule), returning the machine's `Error::InvalidAdvert`;
  - `effective_created_at_secs`, the clamp that keeps a peer's `created_at`
    from reading more than `FRESHNESS_SKEW_TOLERANCE_MS` ahead of our clock;
  - `advert_valid_until_ms`, the validity horizon's arithmetic: the clamped
    `created_at` plus the maximum age, cut short by the NIP-40 expiration.
- `assemble.rs`: the local advert's assembly. `AdvertTransportSnapshot` is
  the node's snapshot of one transport's advertisable inputs (re-exported by
  the shell's `driver.rs` at its old path). `learned_wanted` names the
  transports whose public address must be learned first (advertised, public
  UDP, bound to a wildcard, no external address), in snapshot order, and
  `assemble` turns the snapshot and the learned addresses into the advert
  body, with an `AssemblyNote` for each transport it had to leave out. The
  precedence per transport (external address, then a specific bind address,
  then the learned one) and the endpoint order are the node's long-standing
  ones; the shell learns the addresses and logs the notes.
- `ingest.rs`: the checks every advert a relay delivers passes before it is
  cached. `check` runs, refusing at the first that fails, the validity
  horizon (`valid_until_ms`, which reads the event's NIP-40 expiration as
  the relay client does) before anything else is read, then `screen` (the
  `protocol` tag and the 8 KiB content bound), then `authentic` (the
  event's id and signature, checked by the node itself rather than left to
  the relay client), then `decode` (the JSON, the 32-entry list bound
  before unusable endpoints are dropped, then `validate_overlay_advert`),
  then the clamp on a future `created_at`. It returns the `Checked` advert
  or a `Refusal` naming the step that refused it: `Expired`, `Forged` or
  `Invalid`. The cheap refusals run before the signature check, so a
  flood of events that are not our adverts costs no signature check, and a
  forged advert is never decoded. All three ingest paths call it: the
  subscription's stream, the targeted fetch on a dial, and the
  stale-advert refetch, which calls it only after comparing `created_at`
  with the cached entry's, and which drops events that are not `authentic`
  before that comparison. The author test (`newest_by_author`, which reads
  the `pubkey` field only, and the fetch's own test) stays with each path.
  `parse`, `screen` then `decode` with no signature check, is test-only.
  Also the lifetime arithmetic (`max_age_ms`: two advert lifetimes) and
  `clamp_own`, which cuts our own advert's lists to the bound peers accept
  and names each list it cut.
- `cache.rs`: `Cache`, the peers' adverts keyed by author npub. An author
  already cached has its entry replaced by an advert no older than it; a new
  author is admitted while there is room; at the cap, a protected author (a
  configured peer, or one with an established link) takes the slot of the
  unprotected entry admitted most recently, and anyone else is refused, so a
  flood of new keys cannot evict an honest author. An entry past its horizon
  keeps its slot, serving nothing, for one republish interval of grace. It
  hands open discovery the protected entries and a uniform random sample of
  the others, drawn from the caller's entropy, and keeps the latch that lets
  the cache-full warning through once until the cache has been below its cap
  for a minute, on instants of any `fips_core::time::Instant` type.
- `publisher.rs`: `Publisher`, the advert this node wants to publish and
  whether it advertises at all, and `plan_publish`, which stamps our
  identifier and version, drops endpoints no peer could use, and applies the
  `udp:nat` rule. `PublishSchedule`, when it is published: on request and
  every refresh interval from start, one publish at a time, with requests
  made during one coalesced into one more after it. `LocalTransports`, the
  node's transports and the public addresses learned for them, observed one
  at a time in snapshot order and kept for their time to live (a success
  for `max(advert_refresh_secs, 60)` s, a failure for 60 s), and the
  requests waiting for the advert assembled from them.
- `tests/`: the unit tests of `assemble.rs`, `cache.rs`, `ingest.rs` and
  `publisher.rs`.

## Rules for changing it

- The cache's map is keyed by author npubs, which peers choose, so it is a
  `fips_core::utils::hash::HashMap` under a hasher the shell keys from the
  host's entropy; nothing decides by its iteration order. The protected set
  is only tested for membership and is a `BTreeSet`.
- The rendezvous machine owns the cache and the publisher outright; nothing
  here locks. The cache also says when its next prune is due
  (`earliest_expiry_ms`) and when its cache-full latch would be released
  (`bound_release_at`), so the machine prunes on a step past the first and
  sets a deadline at the second.
- The shell's `NostrRendezvous::validate_overlay_advert`,
  `parse_overlay_advert_event`, `newest_event_by_author` and
  `compute_advert_valid_until_ms` are test-only wrappers over `ingest.rs`,
  kept at their paths for the shell's tests; they map the machine's error
  onto `BootstrapError` with the same text, and a JSON error onto
  `BootstrapError::Serde`.
- The refusal texts are what operators see in the log and what the shell's
  tests read; change them only on purpose.

## Tests

The assembly, the cache and the publisher are tested in `tests/`. The rules in `mod.rs`
are tested through the shell, in `src/nostr/tests/mod.rs`: validation, the
endpoint filter, the never-routable ranges, the clamp and the validity
horizon; so are the cache's lapse grace (its `advert_lapse` module) and the
runtime's use of the cache.
