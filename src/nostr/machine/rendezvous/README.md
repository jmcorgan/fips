# src/nostr/machine/rendezvous

The rendezvous machine: `Rendezvous`, the one owner of FRC-1601's state,
stepped by the shell's pump (`src/nostr/pump.rs`). It holds the only copy of
the node key the Nostr code signs with.

## Files

- `mod.rs`: `Rendezvous` and `Now`, the step's two clock readings (a
  monotonic instant for every deadline and schedule, Unix milliseconds for
  what FRC-1601 writes in Unix time). `handle` takes one input, and
  `handle_timeout` runs what is due; `poll_action` hands the shell the
  actions queued, in order, and `poll_timeout` the next deadline.
  `advert_cache` builds the peer advert cache from `Params`. What a step
  does:
  - `Start`: subscribe to the signals addressed to this node and to every
    advert, then publish the inbox relay list, then ask for an advert
    publish; a failed subscribe runs the sequence again after 2 s, doubling
    to 60 s, and a successful one schedules the inbox relay list's daily
    republish. The advert is republished every `advert_refresh_secs` from
    start, not at start.
  - The advert publish: one at a time, plan, clamp, sign, send, with a
    request made during one coalesced into one more after it. A publish
    the client accepted but no relay took (the advert, or the inbox relay
    list) is logged at debug and otherwise treated as sent.
  - `Transports`: observe each wanted public address, one at a time in
    snapshot order, then assemble; the publish waits for the address, and a
    request with a reply (start-up's) is answered once the advert is
    assembled. An observation binds an ephemeral socket and runs the STUN
    client (`machine/stun/client.rs`) over the configured servers on it,
    then closes it; with no servers configured the address is unknown at
    once, with no socket. A learned address is observed again, and the
    advert assembled again, when it ages out, with no new snapshot needed:
    the node sends its transports only when they change.
  - A relay's advert, the node's endpoint and open-discovery queries, the
    stale-advert refetch, protection changes and NIP-42 challenges.
  - A peer's event whose id or signature does not verify is counted in
    `forged` and logged at debug (`EventForged`), with a warning
    (`EventsForged`) each time the count reaches a power of two, as shed
    signals are. The stream counts every forged advert. The dial fetch
    tests the author first, so it counts a forged advert under the peer's
    key only. The refetch drops every forged event before choosing the
    newest, counting each, so what is dropped is treated as if no relay had
    sent it: a forged newer advert does not hold back a genuine refresh,
    and an answer of forged events alone evicts. A traversal's inbox
    lookup drops a forged inbox relay list the same way, counting each, so
    a forged newer list cannot choose the relays our signals go to.
  - Every step ends with a prune once the earliest entry is due to go, and
    the release of the cache-full warning's latch; a deadline at the
    earliest expiry makes the prune happen on time with no input.
- `traversal.rs`: the traversal half, as more of `Rendezvous`'s steps.
  - `Connect`: capacity, the peer's advert (the cache, else a fetch), its
    `udp:nat` endpoint, the peer's inbox relays (a 1.5 s fetch, falling back
    to our DM relays, with any list whose signature does not verify
    dropped first) and the signal relays the pool holds, a socket, the
    local candidates when shared, the STUN client's observation, the offer,
    the wait for the answer, the on-link prefixes, the plan and the punch
    attempt. A connect to a peer whose traversal already runs ends at once
    (`Release`); any failure ends it with `Failed`, carrying the
    `BootstrapError` text, and a success records it and asks to `Adopt`.
  - A signal: the gate (reading whether any traversal of ours awaits an
    answer from the session table), the open, then an answer routed to the
    initiator by the nonce it names, or an offer: the admission slot, the
    bounds, capacity, freshness, the election (suppressing the peer's offer
    re-sends ours once), the replay check, then the same steps to the answer
    and the punch. A refused offer is logged at warn when relay lag cannot
    explain it.
  - `RecordFailure`, `VersionMismatch` and `Capacity`: the node's failure
    record, answered with the time it used, the mismatch cooldown and its
    warning, and whether the node has room. A traversal's success is
    recorded by the machine itself, when it adopts the initiator's socket.
- `status.rs`: `Status`, what the node reads of rendezvous without waiting:
  each peer's failure record, by canonical npub, with the cooldown rule the
  open-discovery sweep checks and the rows `show peers` prints. The pump
  stores the latest one where the node's synchronous queries read it, after
  each step that changed it and before it carries out that step's actions,
  so a reply never arrives ahead of the status it describes.
- `io.rs`: the inputs, actions and replies, and the opaque ids (`ReqId`,
  `ReplyId`, `SubId`, `SocketId`) that tie a result to what asked for it.
  The shell keeps the map from each id to its `oneshot`, task or socket.
- `log.rs`: `Log`, one variant per line the machine asks the shell to log,
  carrying that line's fields. The shell's `log.rs` renders each.
- `tests/`: the machine's tests.

## Rules for changing it

- The machine does no I/O and holds no lock: every relay call, observation
  and log line is an action, and every result comes back as an input. An
  action whose result the machine no longer expects is ignored when the
  result arrives.
- A refetch that refreshes or evicts a peer's advert resets the peer's
  failure streak in the same step as its reply.
- Every check of a traversal keeps the order the code before the machine
  gave it, the skew noted before the answer is checked and the admission
  slot taken before the capacity check among them.
- A traversal's socket is drained by its STUN observation until it ends, so
  no punch is in flight before it; datagrams that arrive between the
  observation and the attempt are kept (up to 64) for the attempt.
