# src/nostr/fixtures/v044

Four events as the deployed nostr 0.44 code emits them, captured together on
2026-11-12 from commit `fe43c61d` (the event builders factored out of the
publish paths) by the generator in `src/nostr/tests/fixtures.rs`. The keys
are those of FRC-1601 Appendix C.1: node A's secret key is `…0003` (test
vector 0 of BIP-340), node B's is `b7e15162…` (test vector 1).

Each file is one JSON object: `captureUnixMs`, the time of the capture in Unix
milliseconds, and `event`, the event exactly as nostr 0.44 serialises it. The
builders read the clock and the OS random source (signatures, NIP-44 nonces,
the wrap key, the seal's backdating), so a capture cannot be repeated byte for
byte. Every time inside an event or a signal body is derived from
`captureUnixMs`, so code that checks freshness or expiry is run at that time.

- `advert.json`: node A's kind 37195 advert, built by `advert_event` with a
  3600 s lifetime and the default `app` as its `protocol` tag. Its content is
  that of FRC-1601 Section 4.2: a `udp` `nat` endpoint with its signal relays
  and STUN server, and a `tcp` endpoint at `fips.example.com:8443`. The `d`
  tag and the content's `identifier` are this branch's `ADVERT_IDENTIFIER`.
- `inbox-list.json`: node A's kind 10050 inbox relay list, built by
  `inbox_list`, naming `wss://relay.damus.io` and `wss://nos.lol`.
- `offer-wrap.json`: a kind 21059 gift wrap from node A to node B, built by
  `signal_event` with a 120 s lifetime, carrying the offer of FRC-1601
  Section 5.2 with its times moved to the capture.
- `answer-wrap.json`: node B's wrap back to node A, carrying the accepting
  answer of FRC-1601 Section 5.3, likewise moved.

The tests are in `src/nostr/tests/fixtures.rs`: each wrap opens with its
recipient's key to the sender and the body above, the advert parses through
`parse_overlay_advert_event` and the inbox list through `inbox_relays`, and
today's builders, run again at the capture time, still emit the same kinds,
tags, authors, contents and signal bodies.

To recapture, run the ignored generator and update the commit above:

```sh
cargo test -p fips-mesh --lib \
    nostr::tests::fixtures::capture_the_v044_fixtures -- --ignored --exact
```

The advert carries its branch's `ADVERT_IDENTIFIER`, signed. A branch with
another identifier recaptures the advert there and records that commit here;
the advert test says so when the identifier differs. The other three files
carry no identifier.
