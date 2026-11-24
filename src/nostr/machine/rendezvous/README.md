# src/nostr/machine/rendezvous

The rendezvous machine: `Rendezvous`, the one owner of the advert half of
FRC-1601's state, stepped by the shell's pump (`src/nostr/pump.rs`).

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
  - Every step ends with a prune once the earliest entry is due to go, and
    the release of the cache-full warning's latch.
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
- A `ResetStreak` is queued before the `Reply` of the same refetch, so the
  streak is reset before the node reads the outcome.
- The traversal flows are still served outside the machine. They reach it
  only through `ResolveAdvert`, and it reaches them only through
  `ResetStreak`, until they move in.
