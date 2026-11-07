# src/transport/tests/conformance

The lifecycle rules every connection-oriented transport keeps, written once
and run against each transport kind. Declared from `src/transport/mod.rs` as
`#[cfg(test)] #[path = "tests/conformance/mod.rs"] mod conformance;`, so the
tests are `transport::conformance::<kind>::<rule>`. The suite is a child of
`transport`, not of any one transport, so it reaches only what a transport
makes visible to the crate: it never touches a pool directly.

## The rules

1. **A deliberate close lets the writer finish what was queued.** Close
   half: a frame queued just before the close reaches the peer, and the
   close still ends the connection. Stop half: stopping the transport after
   such a close ends a writer still draining, within two seconds.
2. **An accepted connection that sends nothing is closed within its
   deadline**, and is not closed before it; one that has sent its first
   frame is not closed by that deadline. The look for a close before the
   deadline comes where the instance chooses (`Accepting::early`), so a
   close between that look and the deadline is not seen: TCP and Tor, in
   real time, look at 600 ms of a 1 s deadline, leaving 400 ms for a loaded
   host. The
   look is timed from before the connect, so a host too loaded to look in
   time fails a `precondition:`, not the rule.
3. **The receive bound is the shared ceiling, `framing::RECV_CEILING`,
   not the local `mtu`.** A frame above the receiver's `mtu` but within the
   sender's is delivered without a receive error, on the connection it came
   on; a frame of the ceiling is delivered; a length prefix claiming one
   byte more closes the connection.

## Files

- `mod.rs`: each rule as a generic function, and the trait it is run
  through: `Closing` (rule 1, close half), `Stopping` (stop half),
  `Accepting` (rule 2), `Carrying` and `Raw` (rule 3). A rule's assertion of
  the behaviour carries a message starting `defect:`, each setup check one
  starting `precondition:`, as `testing/known-defect-lane.sh` requires.
- `kinds.rs`: the listing, and the test that checks it against one handle
  of every kind.
- `tcp.rs`, `tor.rs`, `nym.rs`: each kind's instances. An instance is a
  test that sets the connection up and hands it to the rule. Tor runs over
  a mock SOCKS5 proxy and a directory-mode onion listener bound on
  loopback; Nym over the mock proxy. On this line BLE has no instances:
  its channel pool is its own design, a close still aborts the channel's
  writer and no unproven channel is closed, so the listing exempts it from
  rules 1 and 2 with that reason. The rules ask whether a connection is
  pooled through each transport's test-only `has_connection`.

## The listing

`kinds.rs`'s `listing` is an exhaustive `match` over `TransportHandle`,
with each variant's `cfg` and no wildcard arm, so a new transport kind fails
the build (E0004) until it has an arm. A connection-oriented kind's arm
gives each rule either `Instance`, naming the instance tests by their
function, or `Exempt` with the reason the rule does not apply. A listed
instance that does not exist fails the build at the listing: E0425, or a
type error where the rule's own function of the same name is in scope. A
connectionless kind is `Connectionless`; the loopback test double is
`TestDouble`.

The test in `kinds.rs` builds one handle of every kind with its inert
constructor and checks that the listing agrees with the type the handle
reports, and that no exemption is without a reason.

## Adding a transport kind, or a rule

- A new kind: add its arm to `listing`, its instances in a file named for
  it, and its handle to `every_kind`. Exempt a rule only with a reason a
  reader can check against the code.
- A rule a kind does not keep yet is still an instance: the test is
  ignored as `known defect: ...` and listed in `testing/ignored-tests.txt`,
  and the fix removes both.
- A test hook a rule needs (a shorter deadline, a seeded writer) is a
  `#[cfg(test)] pub(crate)` method on the transport, as
  `set_first_frame_timeout` and `stuck_writer` are.
