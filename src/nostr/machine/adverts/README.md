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
    a Tor address, and a UDP or TCP address with a nonzero port whose host is
    not one `is_unroutable_direct_advert_ip` refuses (the never-punchable,
    private and documentation ranges of `punch/plan.rs`);
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
  cached. `check` runs the validity horizon (`valid_until_ms`, which reads
  the event's NIP-40 expiration as the relay client does) before anything
  is parsed, then `parse` (the `protocol` tag, the 8 KiB content bound
  before decoding, the JSON, the 32-entry list bound before unusable
  endpoints are dropped, then `validate_overlay_advert`), then the clamp on
  a future `created_at`. All three ingest paths call it: the subscription's
  stream, the targeted fetch on a dial, and the stale-advert refetch, which
  calls it only after comparing `created_at` with the cached entry's. The
  author test (`newest_by_author`, and the fetch's own test) stays with
  each path. Also the lifetime arithmetic (`max_age_ms`: two advert
  lifetimes) and `clamp_own`, which cuts our own advert's lists to the
  bound peers accept and names each list it cut.
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
  `udp:nat` rule.
- `tests/`: the unit tests of `assemble.rs`, `cache.rs`, `ingest.rs` and
  `publisher.rs`.

## Rules for changing it

- The cache's map is keyed by author npubs, which peers choose, so it is a
  `fips_core::utils::hash::HashMap` under a hasher the shell keys from the
  host's entropy; nothing decides by its iteration order. The protected set
  is only tested for membership and is a `BTreeSet`.
- The runtime holds the cache and the publisher each behind one
  `std::sync::Mutex`, and binds what a call returns before acting on it, so
  no lock is held while it logs or awaits.
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
