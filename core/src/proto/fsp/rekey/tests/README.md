# core/src/proto/fsp/rekey/tests

The session rekey profile's tests, attached from `xx.rs` with `#[path]`
so they can name its private items.

- `xx.rs`:
  - `xx_profile_writes_and_reads_the_handshake_and_frames_next_sends_byte_for_byte`:
    the setup, both ack shapes and both msg3 shapes equal what next's
    plain code writes; next's responder reads each msg3 and its payload;
    malformed setups fail `valid`; a failed ack read leaves the attempt
    readable; `complete` takes either msg3 shape and refuses a tampered
    one; frames open under next's plain session over the 12-byte header
    and back; the prompt is a `CoordsWarmup` that `is_probe` takes and
    nothing else is.
  - `xx_reply_reads_the_payload_on_its_fork`: a plain responder reads the
    msg3 `reply` writes after an ack with a payload and reaches the same
    handshake hash, and `complete` reaches a plain initiator's.
  - `two_xx_session_machines_open_a_session_and_rekey_it`: one first
    handshake (payload on the ack and msg3) and one rekey (none) between
    two machines, with the responder's prompt and the cutovers, and
    frames opening at both ends.
  - `restarted_peers_final_with_payload_completes`: a peer that restarted
    opens with a payload-bearing msg3 against a machine holding the
    session, which completes it and reports the restart.
  - `xx_reply_from_another_key_keeps_the_attempt`: an ack from a third
    key reads, fails the bond, sends no msg3 and leaves the attempt and
    its deadline as they were; the peer's ack then completes it.
