# core/src/proto/fmp/rekey/tests

The link rekey profile's tests, attached from `xx.rs` with `#[path]` so
they can name its private items.

- `xx.rs`:
  - `xx_profile_writes_and_reads_the_handshake_and_frames_next_sends_byte_for_byte`:
    msg1 and msg3 equal what next's plain code writes from the same
    entropy and state; next's leg reads the msg3 with its payload and
    declaration; a failed msg2 read leaves the attempt readable; a reply
    with no index to declare is refused; `read_final` takes the msg3 to
    the same facts and session as the plain read, and a tampered copy
    hands its lease back and leaves the leg readable; frames sealed by
    the profile open under next's plain session and back; the prompt is
    a Heartbeat.
  - `xx_reply_reads_the_payload_on_its_fork`: a plain responder reads the
    msg3 `reply` writes after a msg2 with a payload and reaches the same
    handshake hash, and `read_final` reaches a plain initiator's.
  - `two_xx_link_machines_rekey_through_a_leg_and_the_delayed_cutover`:
    two machines built on one XX link; the initiator's attempt answered
    by a leg stand-in (plain responder code, a leased index), its msg3
    read by `read_final` and handed to the responder as a rekey; the
    initiator cuts over after its delay and resends msg3 until the peer
    is heard, the responder adopts on the first frame, frames open at
    both ends, and every index is accounted for.
  - `lost_xx_final_is_resent_until_heard`: the first msg3 is lost; a
    resend completes the leg and both ends end on the new epoch.
  - `xx_rekey_reply_from_another_key_keeps_the_attempt`: a msg2 from a
    third key reads, fails the bond, sends no msg3 and leaves the attempt
    and its deadline as they were; the peer's msg2 then completes it.
