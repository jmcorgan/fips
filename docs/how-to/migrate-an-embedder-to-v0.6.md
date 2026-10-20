# Migrate an Embedder to v0.6

For code that uses the `fips` library crate (published as `fips-mesh`)
rather than running the `fips` daemon. Each section names one change in
v0.6.0 that can stop such code from building, what to do about it, and
the CHANGELOG entry that records it. Changes that touch only the daemon,
its configuration or the wire are in the CHANGELOG and the release
notes, not here.

## `ActivePeer` no longer exposes its session slots or its rekey state

**What changed.** The methods of `fips::peer::ActivePeer` that read or
change its Noise sessions, their indices, the K-bit epoch, the session
time base, the stored link-setup msg2, the peer's startup epoch and the
rekey cycle are no longer public. These are now private to the crate:
`with_session`, `has_session`, `noise_session`, `our_index`,
`their_index`, `session_elapsed_ms`, `set_handshake_msg2`,
`handshake_msg2`, `remote_epoch`, `session_established_at`,
`link_established_at`, `rekey_jitter_secs`, `current_k_bit`,
`rekey_in_progress`, `pending_our_index`, `pending_their_index`,
`previous_our_index`, `previous_session`, `pending_new_session`,
`is_draining` and `rekey_our_index`. These are gone, because the rekey
state machine now holds the state they reached: `noise_session_mut`,
`replace_session`, `session_start`, `is_rekey_dampened`,
`record_peer_rekey`, `previous_session_mut`, `pending_new_session_mut`,
`set_pending_session`, `cutover_to_new_session`, `handle_peer_kbit_flip`,
`drain_expired`, `complete_drain`, `abandon_rekey`, `set_rekey_state`,
`awaits_msg2`, `complete_rekey_msg2`, `needs_msg1_resend`, `rekey_msg1`
and `rekey_msg1_resend_count`. Four methods nothing called are also
gone: `set_their_index`, `clear_handshake_msg2`,
`set_rekey_in_progress` and `set_msg1_next_resend`.

**Why.** The node drives these through its own handshake and rekey
handlers, and calling them from outside could leave a peer's sessions
out of step with the node's index tables. Keeping them private lets the
rekey code change in later releases without breaking the library's
interface again.

**What to do.** Code that calls none of the methods above needs no
change: the identity, addressing, tree position, filter, link statistics,
MMP and heartbeat accessors are unchanged. For the session and
rekey figures a monitoring tool shows, read the node's `show_peers`
control query, which reports for each peer its session index, its
session's send and receive counters, the K-bit, and whether a rekey or a
drain is in progress. No replacement is offered for driving a rekey from
outside the node.

**Recorded in** the CHANGELOG's v0.6.0 Removed section: the entry on
`ActivePeer`'s session-slot and rekey methods.
