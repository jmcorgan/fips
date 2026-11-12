# core/src/proto/path/tests

Unit tests for the files one level up. `mod.rs` is the module's own
tests module, `proto::path::tests`, declared from the module root, and
declares `shell.rs`, `exchange.rs`, `account.rs`, `liveness.rs`,
`active.rs`, `admit.rs`, `beacon.rs`, `capability.rs`, `close.rs`,
`charge.rs`, `choice.rs`, `connect.rs`, `damping.rs`, `disabled.rs`,
`floor.rs`, `hold.rs`, `intake.rs`, `mtu.rs`, `pin.rs`, `renew.rs`,
`returns.rs`, `sim.rs`, `stub.rs`, `verdict.rs` and `view.rs`,
which drive
the machine, `Bundle`,
through its public interface only. Every other file is attached from
its source file with
`#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so it is a child
module of that file, sees its private items and keeps its test names.

- `account.rs`: attribution of authentic frames
  (`proto::path::tests::account::...`) through `Bundle::account`: a frame
  counts on the path of its transport and address and on no other, an
  ack's `rx_frames` and `rx_bytes` are its path's own with the probe's
  frame included, a probe naming another path and a matched ack from
  another pair count on the path they concern, a frame from no path
  counts nowhere and changes no path, a link of only its original path
  roams as the set does, a path message never roams and a probe from a
  new address beside the one path adds a path, the one path left once
  the original is gone does not roam, one of two paths moves no address,
  receiving never changes the active path, the peer's
  active path follows its latest message that is neither a datagram nor
  a path message (each type tried), the sample flag, that `account` and
  `charge` allocate nothing, `charge` through each of its four results
  (counted by the test build's allocator, which is first shown to
  count), that a path of a capable link released at the close or by an
  eviction is kept open only when it is the peer's active path, and that
  every path of a link whose peer is not capable is kept open at the
  close and at a discard, enabled or disabled; that a bundle with
  multipath disabled roams its one path on a path message's frame and
  an enabled one does not; and that a slot written through `driver_mut`
  comes back from `close` on its own path.
- `active.rs`: the active path (`proto::path::tests::active::...`),
  driven through `Bundle`'s inputs in the shell: the mandatory switch to
  a Live path when the active path goes Suspect, and to an acked Suspect
  path when it goes Dead with nothing Live; a Suspect active path kept
  beside a faster Suspect path; a Dead active path kept, with nothing
  orphaned; the acked Dead paths probed at once when the active path
  leaves Live, goes on to Dead, or is discarded with nothing Live; an
  acked standby being probed again after Dead probed at once when the
  active path fails with nothing Live, whether the peer's probe or its
  carrier's return brought it back, and not once it has sent its
  discovery probes, after which it goes Dead; a
  removed transport's paths discarded and released, with the handover
  to the best Live path, else the acked Suspect path, else the acked Dead
  path most recently Live, and none when a standby's transport goes; the
  path made active in place of a discarded one probed at once when
  nothing is Live, Suspect or probed again after Dead;
  `keep` on the peer's active path only; `Orphaned` once when no
  original or acked path is left, after which the bundle answers
  nothing and `account` binds nothing and allocates nothing; a Dead
  active path discarded at its grace in the step another path turns
  Live; and no switch to a path not acked.
- `admit.rs`: path policy in the machine
  (`proto::path::tests::admit::...`), driven through `Bundle`'s inputs in
  the shell: candidates on another anonymity class (Tor and Nym beside a
  clear link, a clear one beside a Tor link), of another kind with kinds
  unmixed, on a transport the node would not dial, and on one whose role
  is never are refused and never probed, naming the rule; received
  probes that would create a path across classes, of another kind, on a
  transport that would refuse the peer's handshake or whose role is
  never are refused and not answered; with kinds mixed a path of another
  kind is probed and created; a path takes the kind of its address
  unless its transport has one; a probe that finds a held path, the
  original on a transport that only dials, is answered and its
  identifier learned; a probe that would move a path to an address of
  another kind is refused and moves nothing, while an ack from such an
  address still counts and moves nothing; the original path moves to a
  new address whatever the rules; the link's class and kind are its
  original path's; a refused probe still makes the peer capable; a
  Dead path on a transport the node would not dial is not probed on
  carrier's return, on a report of its pair, over minutes of polls at
  the Dead cadence or when the active path leaves Live with nothing
  Live, and is brought back and probed at once by the peer's probe,
  which is answered; the peer's probe on a Dead path, answered whatever
  the rules, brings it back and probes it at once where the node accepts
  the peer, whether or not it dials it, and leaves it Dead where it does
  not, unprobed too where it neither dials nor accepts; an acked Dead
  path the node would neither dial nor accept on is not probed at once
  when the peer's `ACTIVE` on it clears; a Live standby on a transport
  that stops dialling is still probed while Live and Suspect and not
  once Dead; and the original path, Dead, is probed at the Dead cadence
  whatever the dial fact, and brought back by the peer's probe whatever
  the rules.
- `beacon.rs`: an unauthenticated beacon at a path
  (`proto::path::tests::beacon::...`), driven through `Bundle`'s inputs in
  the shell: a beacon at a Probing path never acked with no probe
  outstanding and its next not yet due sends that probe in the step; a
  second in the same state brings nothing forward, and one after the path
  enters Probing again does; one while a probe is outstanding or while
  the next is already due is not taken as the path's one; on a path that
  has stopped answering the probe still waits for the floor; on an
  unconnected path on a connection-oriented transport it asks for the
  connection now, and while that connection is pending it changes
  nothing; at a Live, Suspect or Dead path, an acked Probing path or an
  unheld pair it changes nothing; it makes no peer capable; a disabled
  bundle discards it; and beacons at every poll of a Probing episode add
  no probe and cut short one gap of its ladder only.
- `capability.rs`: learning that a peer is capable
  (`proto::path::tests::capability::...`), driven through `Bundle`'s
  inputs in the shell: a capability probe is 27 bytes on the original
  path, with its identifier, `ACTIVE` and no capability bit; none goes
  and nothing wakes over two simulated hours with no candidate, nor for
  a candidate the rules refuse or one held back by its interface leaving,
  until the interface returns, nor after that return for one its source
  unlisted while it was held back; probing stops when the last candidate
  is unlisted and resumes where it stopped when one is reported again; a
  change in the facts takes effect at the next gate and the next
  admission; a roam of the original path off a candidate's pair wakes the
  probe; three probes over 30 seconds, then a gap doubling to ten
  minutes, twelve in the first hour and six in the second; the link
  reported not capable once, at 20.4 seconds; an answer in time makes
  the peer capable, learns its identifier, samples a round trip and
  probes the candidates, makes a Suspect original Live, and from a new
  address moves the original whatever the rules and counts there; one
  after its timeout is late, polled at that timeout or not, and a late
  one gives a round trip only; capability probes take consecutive ids
  of the original path's sequence; a peer turning capable with a probe
  outstanding is never reported not capable after, and that probe's
  answer gives a round trip only;
  unanswered capability probes leave the original path Live with no
  miss; one probe at a time when the gap is under the timeout; none
  once the peer is capable; and a new link starts a new first round.
- `capable.rs`: tests for `capable.rs`
  (`proto::path::capable::tests::...`), the capability record on its
  own: the draft's schedule (0, 10, 20, 50 seconds and on, twelve in the
  first hour, six in the second, every later gap ten minutes); nothing
  due while a probe is outstanding; an answer matching only the
  outstanding probe of its path and only before its timeout; and the
  first round reported unanswered once.
- `candidate.rs`: tests for `candidate.rs`
  (`proto::path::candidate::tests::...`), the candidate table on its
  own: a repeat changes only recency while a new source or a request is
  fresh and releases a held-back entry; an entry forgotten when its last
  source unlists it, unless it is held back; release and absence touching
  one transport only; pruning only the released entries no source lists
  and no path holds; forgetting a removed transport's entries; the
  order a full table replaces entries in, never a path or a held-back
  entry some source lists, and the report dropped when nothing may go;
  and that the table allocates nothing over rounds of every operation,
  with the counter first shown to count.
- `charge.rs`: authentication failures
  (`proto::path::tests::charge::...`), driven through `Bundle::charge`
  and `Bundle`'s inputs in the shell: failures from a pair that is
  neither the original path nor acked (a Probing path, an unknown
  address on a held transport, a held address on another transport)
  count toward nothing; an acked Dead path counts its failures, and at
  the limit stays Dead with a warning and its grace unchanged; at the
  limit with another path Live, or an acked Suspect one, the path trips,
  and the next step marks it Dead as of the failure that tripped it and
  moves the link off it;
  failures on an acked standby mark it Dead and leave the active path
  alone; with no other usable path (a link of one path, the other path
  only Probing, or the other acked and Dead) the path is kept and one
  warning returned; an authentic frame resets only its own path's count,
  accounted or, through `Bundle::authentic`, not, and one from a pair no
  path holds resets none;
  the warning comes once in 25 failures; a recorded trip makes the next
  wake due at once; a trip no longer possible when the step comes, since
  the other path tripped first, is dropped; and an orphaned bundle
  counts nothing.
- `choice.rs`: which path carries a link
  (`proto::path::tests::choice::...`), driven through `Bundle`'s inputs
  in the shell, each path's round trips set by a `Net` from its first
  probe on: when the active path fails, a standby with enough round-trip
  samples is taken over a faster one with too few, and the path with the
  least score over the one with the least latest round trip. While the
  active path is Live: a standby that scores better but not by the
  margin is never taken; a degraded active path is left exactly one
  dwell after the margin first holds, the dwell set to end between probe
  wakes so only its own wake ends it; the dwell ends when the margin
  stops holding, and starts again when its target leaves Live and comes
  back; a standby is not taken before it has `min_samples` samples, and
  is taken one dwell after its last one comes; a path that comes to
  rank first inside a dwell toward another runs its own dwell, from
  then; a dwell ends while the active path is not Live, leaving no wake
  behind it; and a path that ties with the active one never takes its
  place. By role: a backup path
  that scores better by the margin is never taken while a normal one is
  Live; a backup active path yields at once to a normal path that has
  just turned Live with one slower sample; a backup path takes the link
  when the active path fails and gives it back at once when that path
  answers again; a path whose transport has since been set never ranks
  below a backup one in a mandatory change, whatever it scores; with
  equal round trips the preferred path carries the link whichever
  transport carried the first handshake, taken one dwell after its
  second sample when it did not; and a preferred active path that scores
  outside the margin of the best gives way after the dwell, also when a
  second preferred path within the margin of the best scores within the
  margin of it. By link
  MTU: an active path too small for a `FilterAnnounce` gives way to a
  slower one that carries it, one dwell after that path's second
  sample; a mandatory change takes a path that carries it over one that
  scores better and does not; with no Live path that carries it the
  score decides as before; a normal active path too small for it is
  kept over a backup path that carries it; and a link MTU of exactly
  the frame's 1,071 bytes carries it, one byte less does not. By
  medium: a cable within the margin of a better-scoring wireless
  network takes the link one dwell after its second sample, and a link
  made on a cable stays there; a mandatory change takes a cable within
  the margin over a better-scoring wireless network; outside the margin
  the score decides, both ways; an unknown medium on either side keeps
  the rule of score alone; a cable too small for a `FilterAnnounce`
  does not take the link from a wireless network that carries one; a
  preferred wireless network within the margin keeps the link over a
  cable; an active path outside the margin of the best, a cable or
  of unknown medium, gives way to a cable within it; and under load that
  follows the link, a cable within the margin of a wireless network
  faster at its best keeps the link until the load has lasted the
  horizon and moves at most twice a horizon, as does a cable faster at
  its best, and a wireless network faster at its best than a cable
  outside the margin of it keeps the link until the load has lasted
  the horizon and moves at most twice a horizon. Its helpers
  that build a node, set roles and round trips, offer a candidate and
  run the `Net` are shared with `pin.rs`.
- `close.rs`: closing a path (`proto::path::tests::close::...`), driven
  through `Bundle`'s inputs in the shell: a removed transport sends a
  `PathClose` for each of its paths on another Live path, before the
  paths are discarded; an interface leaving does the same; a carrier loss
  names the peer's identifier for each path on that transport and, with
  our active path on it, goes on the Live path of lowest index
  elsewhere; a close goes on our active path when it is Live and
  elsewhere, ahead of a Live path of lower index; no close goes on the
  path it closes, so none is sent when that path is the only Live one;
  none goes to a peer not known to be capable; and none is sent for a
  path whose identifier the peer never gave.
- `connect.rs`: candidates on connection-oriented transports
  (`proto::path::tests::connect::...`), driven through `Bundle`'s inputs
  in the shell: such a candidate has a connection asked for before it is
  probed, and is probed at once, padded, when it opens, and never
  connected again, a report of a connection it did not ask for changing
  nothing; a candidate on a connectionless transport is probed
  at once; each failed connection counts as one unanswered discovery
  probe, the next asked for on the doubling discovery schedule, and the
  eighth makes the path Dead, after which it is neither connected nor
  probed; nothing is probed or timed for a path while its connection is
  pending, over minutes of polls and an early probe asked for by the
  peer's `ACTIVE` turning off; and a path a probe created needs no
  connection.
- `damping.rs`: discretionary changes away from a loaded active path
  (`proto::path::tests::damping::...`), driven as `choice.rs` drives its
  tests and with its helpers and `pin.rs`'s `pin`, load being a rise of
  p's round trip from 5 or 10 ms to 200 ms at 40 s: a standby that
  scores better than p over the window under the load, but is slower than
  p at its best, does not take the link before the horizon has passed;
  once p's score over the horizon has risen past it by the margin it
  takes the link one dwell later, the dwell set to end between probe
  wakes; a standby faster at its best than p, within the margin of it
  idle, takes the link one dwell after it leads p over the window, not
  held; and a carrier loss and a pin still move the link at once.
- `disabled.rs`: a bundle with multipath disabled
  (`proto::path::tests::disabled::...`), driven through `Bundle`'s
  inputs in the shell: given the peer's probes, candidates, an ack, a
  close and connection reports, and minutes of polls, it sends nothing
  and asks for no connection, where an enabled bundle given the same
  inputs answers, probes and connects; each of those inputs leaves it
  as it was, with no output, no candidate held and the peer not made
  capable; the same frames, failures, carrier and
  presence events, and then the interface leaving or the transport
  removed, give the same results and outputs as on an enabled bundle,
  the path released and the bundle orphaned; and, beside an enabled twin
  given the same candidates, probes, acks and minutes of polls, which
  sends a capability probe and wakes, it holds no candidate, sends
  nothing and never wakes.
- `floor.rs`: the floor on a path that has stopped answering
  (`proto::path::tests::floor::...`), driven through `Bundle`'s inputs in
  the shell and checked against the shell's `floor_breaks` and
  `free_after`: a Dead path under a 100 ms standby interval held to it;
  a path silent for `PATH_SILENCE_MAX` held to it while Live or Suspect;
  a standby answered in time while its round trip grows to 20 s, then
  cut, held to it from `PATH_SILENCE_MAX` after its first probe since
  the last answer, which comes before it is Dead;
  a path brought back by carrier's return or by finding the peer again
  held over its eight discovery probes, its first at the floor's next
  instant and counted, or in the revival's step, counted, once the floor
  allows it though the Dead cadence's next probe is further off; one
  brought back by the peer's probe starting the normal discovery ladder
  afresh; an answer in time ending the stop and a late one leaving it in
  force; the early probe on the peer clearing `ACTIVE` and the Section
  5.7 probe at once neither held nor counted; a held probe waking at the
  floor's instant and not at each interval; the floor capped by the
  bound, not `Config::dead_interval`; a connection opened for a counted
  slot, after the revival's own connection took the first, starting the
  next gap at its probe; a stopped Probing path
  keeping its stop when the peer's probe arrives; the active path, silent
  for 20 s with no carrier change, Live again within 1.5 s of the
  outage's end; its re-check every second on its own cadence until 30 s
  after it went silent, at most one probe a second, then gaps that grow
  again to the cap (checked against the file's own `recheck_breaks`); a
  silent standby keeping the doubling while the active path answers; the
  silent active path brought back by the peer's probe within its span
  probed at once; the re-check probes of a path that carried the link
  going at the size it proved on a connection-oriented transport, not
  down the ladder; and such a path on a connectionless transport, whose
  wire returns narrower than the size it proved, stepping down the ladder
  and Live again within 5 s.
- `hold.rs`: the hold on a link's cost across a change of active path
  (`proto::path::tests::hold::...`), driven as `choice.rs` drives its
  tests and with its helpers and `pin.rs`'s `pin`, the link's cost set in
  `Node::cost`: a pinned change holds the cost from before it past the
  switch dwell until the second receiver report after it, and no longer
  once both have passed; reports with no hold in force leave the cost as
  measured and count toward no later hold, which waits for two reports
  of its own; a report stepped in the very step that changes the path,
  found by a first run with polls only, while the hold before it owes
  one report, neither lets the cost jump at the change nor counts
  toward the new hold; a change during a hold keeps the cost already
  held, with the dwell counted from the new change; a mandatory
  change by carrier loss, a handover by removal, a discretionary change
  by score and a pinned change each hold the cost; and `holding` is
  false with no hold, true from a change, still true after the hold has
  ended while only polls made before the next wake are stepped, which
  the shell checks change nothing, and false after the next step that
  is not such a poll.
- `intake.rs`: the candidates a bundle holds
  (`proto::path::tests::intake::...`), driven through `Bundle`'s inputs
  in the shell: candidates held whatever the capability and the rules; a
  candidate of a capable peer probed at once, and repeats, of it and of
  one refused by the rules or for room, giving nothing more; a beacon
  candidate never moving a path, a Suspect active one or a peer's one
  path included; the ninth candidate replacing the least recent one that
  is not a path; a held-back pair its source still lists never probed
  over hours of repeats on a full table; turning capable probing every
  held candidate the rules allow and none held back by its interface
  leaving; a discarded path's pair held back until
  its source reports it afresh, or until its transport regains carrier;
  an interface leaving holding back every candidate on it, with or
  without a path, and its return probing them as new paths, a path the
  peer created among them; a candidate unlisted while held back forgotten
  at its release unless it is then admitted; a path
  evicted to make room held back; a removed transport's candidates
  forgotten; a fresh report from local discovery releasing the held-back
  pairs on its transport and bringing back its Dead paths; an hour of
  beacon repeats sending nothing; a disabled bundle holding nothing; and
  a candidate a rule refused admitted at the next poll after the facts
  change, refused again by a poll only when the refusing rule changes,
  and, finding no room, refused once and left for its next trigger.
- `exchange.rs`: the probe exchange that proves a path
  (`proto::path::tests::exchange::...`), driven through `Bundle`'s inputs
  in the shell: the original path at the start, path identifiers and
  `probe_id`s from the host's entropy source (the start random, each
  probe one more, wrapping to zero), that nothing is admitted and only a
  capability probe sent before the peer is capable and that any path
  message makes it capable,
  candidates admitted and probed padded to the link MTU, then, toward a
  receiver that drops every frame over 1000 bytes, three quarters of the
  padded size after the first padded one times out, proving that size,
  which the search may then raise within the receiver's, while a
  padded probe sent before a change of state and timing out after it
  leaves the next probe padded, the receiver's
  lookup order (the peer's identifier, then the pair, then a new path,
  within the limits), the ack's length and `rx_time_us`, matching an ack
  on (`echo_path_id`, `probe_id`) on any transport, learning the peer's
  identifier only from a match, the round trip and proven MTU of a
  match, that a path a probe created stays Probing until our own probe
  is answered, `ACTIVE` on our active path only, no aggregation offered,
  `PathClose` naming our identifier, a Dead path revived by a probe, the
  address moves of probes and acks, none of the link's lone original
  path, also after a second path is discarded, and the move of a lone
  path that is not the original, the eviction of a Dead path and the
  release of every path at `close`.
- `liveness.rs`: each path's liveness
  (`proto::path::tests::liveness::...`), driven through `Bundle`'s inputs
  in the shell, polling at each `next_wake` and answering probes at the
  instant they go: the cadence of the active path, a standby, one the
  peer marks `ACTIVE` (at once, from the first answer that says so), and
  a link of one Live path (none); a path answered back to Live from Dead
  probed at its Live cadence from then on, not when its Dead interval
  ends; three
  unanswered probes making a Live path Suspect while frames still arrive
  on it, and one or two not; detection of a failure 800 to 1000 ms after
  it starts; the retire to Dead after ten more and the Dead cadence; an
  answer bringing a Suspect and an acked Dead path back to Live; a path
  never answered given up after eight probes on the doubling schedule,
  and never Suspect; a late answer, late too when the host did not poll
  between its probe's timeout and its arrival; which timeouts count; the
  probe
  timeout of three round trips; the grace, with acked Dead paths kept
  while nothing is Live and discarded once a path is; a forgotten path
  not probed again until its source reports it afresh; carrier's return and leaving
  Dead with a fresh count, its discovery probes, the first included,
  then held to the floor of the stop it kept; carrier loss and
  unreachable sends; a close of a Suspect path; a peer not known to be
  capable; the early probe on
  the peer's `ACTIVE` turning off, and dropped when the ring is full;
  the ETX in Suspect; `next_wake`; no probe over the link MTU; the
  sizes of unanswered Probing and Dead probes stepping down the ladder,
  padded first, then three quarters and half of it, then the smallest,
  and padded again; the cadence probes of a path answered back to Live,
  counted apart from the padded search probe beside one of them; and a
  Probing path held to eight probes while the peer's `ACTIVE` on it is
  set and cleared every 150 ms or every 40 ms, sending all eight when
  the flag never changes, and dropping a probe asked for at once after
  its eighth. A path brought back from Dead by carrier or by the peer's
  probe, with a probe of its Dead cadence still outstanding, sends eight
  probes while Probing, since that probe's timeout counts as no miss;
  an answer to it before its timeout still makes the path Live, and one
  after it is late and leaves the path Probing.
- `live.rs`: tests for `live.rs` (`proto::path::live::tests::...`): a full
  ring refuses a probe and spends no `probe_id` on it, an answer takes its
  probe and leaves the rest in send order, the round-trip window keeps the
  least sample of its span and gives up its oldest when full, the horizon
  keeps an idle sample a loaded window has lost until its span and the horizon
  have passed, and at a 200 ms cadence keeps a later fast sample for the
  horizon after it, delivered probes bring the ETX toward one at the long
  average's rate, the receive counts wrap modulo 2^32, a path's count of
  authentication failures saturates rather than wrapping, a stop keeps its
  first instant and its gaps double up to the bound, a stop on a path that
  left Live as the active path keeps a 1 s gap until 30 s after it went silent
  and then doubles, taking that span once per departure from Live, while a
  standby's stop takes none and the active path at its stop, with no silence
  clock, takes it from the stop, the silence clock starts at the earliest
  probe since the last matching answer, only an answer in time is a matching
  one, a connection's slot moves the next free instant to its opening without
  doubling, a probe sent before the path left Dead times out uncounted while
  an answer to it in time still matches, and the first counted `probe_id` is
  dropped once no probe before it is outstanding.
- `mod.rs`: declares `shell`, `exchange`, `account`, `liveness`,
  `active`, `admit`, `beacon`, `capability`, `close`, `charge`, `choice`,
  `connect`, `damping`, `disabled`, `floor`, `hold`, `intake`, `mtu`, `pin`,
  `renew`, `returns`, `sim`, `stub`, `verdict` and `view`, and
  checks the module's source (`proto::path::tests::...`): the module
  root still denies
  wildcard match arms; no source file defines a `set_` setter, with a
  planted setter found and a count of the source files on disk; and no
  test file but `set.rs` calls the set's methods that change a path's
  state, address or standing (`transition`, `mark_dead`, `mark_acked`,
  `learn_peer`, `activate`, `readdress`, `discard`), with a planted call
  found and a count of the test files on disk. The names are built with
  `concat!` there, since that file is one of those scanned.
- `mtu.rs`: the size a path proves (`proto::path::tests::mtu::...`),
  driven through `Bundle`'s inputs in the shell, behind a stand-in hop
  that answers at once each probe up to a given size: a Probing path
  across a hop narrower than its link MTU proving three quarters of the
  padded size; a path whose probes all go unanswered stepping down the
  ladder and starting again; one that carries only the smallest size
  proven with no MTU; after loss stepped the ladder down, the search
  proving the link MTU again, with each change reported once in
  `Output::Proven` in frame bytes; the search climbing to within 32
  bytes of the hop's size, stopping, and starting again ten minutes
  after it ended; a lost search probe neither a miss nor an ETX sample,
  the path staying Live; no search on a connection-oriented
  transport; and a path proven below the frame of a `FilterAnnounce`
  across a narrow hop, though its link MTU would carry it, not taking
  the link from one that cannot carry it either; and a path on a
  connection-oriented transport proven a rung low by one lost probe
  still carrying it by its link MTU, and taking the link.
- `params.rs`: tests for `params.rs` (`proto::path::params::tests::...`):
  the draft's values field by field, the refusal of a zero in each
  interval and count with the name it carries, of a switch margin below
  1.0 or not finite and of a ring over eight, that every error message
  is one sentence with no run of spaces, and the round-trip window's
  30-second floor and its growth with the required samples.
- `pin.rs`: an operator's pin of a link (`proto::path::tests::pin::...`),
  driven as `choice.rs` drives its tests and with its helpers, its own
  `pin` shared with `hold.rs` and `view.rs`, and `onto_q` with
  `view.rs`: a pinned
  path takes the link at once and holds it while another scores better
  by the margin; when the pinned path fails the link leaves it, stays
  off it while it goes unanswered, and the pin is kept, and the link
  goes back to it at the step it turns Live again; a pin of a transport
  takes the better-scoring of its two paths;
  the transport's removal, and its interface leaving, each end the pin,
  so the path at the pair, offered again or released when the interface
  returns, is not moved to when it turns Live; a pinned backup path
  carries the link, and gives it back at once when the pin is lifted;
  after the pin is lifted a better-scoring path takes the link one dwell
  later, not at once; a pin naming no path held is kept, and takes
  the link at the step its path turns Live; and when a pinned active
  path fails, the link goes to another Live path the pin names, not to
  a better-scoring one it does not name. The host's unpin where a
  restart keeps the link is tested at the node in
  `src/node/tests/peer_restart.rs`; the pin kept across a crossed
  handshake in `src/node/tests/crossed_dial.rs` (at msg2 and at msg3)
  and across this node's own later dial in `src/node/tests/control.rs`,
  the peer having dropped the peering first or not.
- `renew.rs`: a link started again at the pair it moved to
  (`proto::path::tests::renew::...`), as a won crossed handshake starts
  one, driven in the shell: renewed at the pair of a path it holds, the
  active path or a standby whose connection the link moves to, that path
  stays under a new `path_id`, Live, acked and active, with its slot and
  its count of failed frames; every other path comes back released; the
  peer is no longer capable and no candidate is held, and its capability
  record starts again: a candidate offered at the renewal gets a new
  first round; the operator's pin and the hold on the link's cost are
  kept; every old path, the one that stays included, is reported ending
  in an `Output::State` with `next: None`, and the new original path
  beginning with `from: None`, each for `Why::Renewed`. Renewed at
  another pair, the link starts on a new path there with a slot of its
  own and no failed frame counted, and the old active path comes back
  released.
- `returns.rs`: the return to the path a mandatory change left
  (`proto::path::tests::returns::...`), driven as `choice.rs` drives its
  tests and with its helpers, p answering in 5 ms and q in 25 ms, within
  the margin of each other, and p's probes unanswered for 2 s from 40 s:
  once p is Live again and scores better than q, by less than the margin,
  the link returns to p one dwell later; and a third path r, offered after
  the change and scoring better than q within the margin, does not take
  the link from q, since only the path the change left needs no margin.
- `rules.rs`: tests for `rules.rs` (`proto::path::rules::tests::...`),
  over a table of facts by transport: the scope of an address, every
  local range and its neighbours outside it, IPv6 with a scope
  identifier, a bare IP, an IPv4-mapped address, a host name, a MAC
  address and text that does not parse; a transport's fixed kind
  winning over the address; each rule refusing and naming itself in
  every check it belongs to (class, kind unless mixed and role in
  `moves`, `probe` and `admit`; accept in `admit` only; dial in `probe`
  only); and that no check allocates, with the counter first shown to
  count.
- `shell.rs`: the shell (`proto::path::tests::shell`, crate-visible for
  the settlement tests). `Checks` holds what the checks remember across
  one bundle's calls and runs them around a step: `Checks::before` ahead
  of it, `Call::stepped` straight after it, before the slots leave the
  outputs through `keep`, and `Checks::after` over the outputs, which
  returns the first rule broken. `Node` calls these around every step and
  panics on the error; another shell holds a bundle to the same rules
  with its own `Checks` and `Slot`. `Node` runs one
  `Bundle` over the test clock, `SeededEntropy` (or another source) and
  `Slot`, a driver slot with a serial number that counts its drops, the
  link's cost the host measures, `Node::cost`, 1.0 unless the test sets
  it and passed in every call's `Env`, and a `Stub` of the host's facts
  (link MTU per transport, 1280 by default; which transports are
  connection-oriented, none by default; and per transport a `Fact` for
  its class, kind, role, medium and whether the node accepts or dials
  the peer, by default clear, fixed Local, `Normal`, unknown, and both,
  the latest fact
  given winning, so `Stub::change` can change one between steps; the
  stub counts its changes, so the shell can tell a poll made with the
  facts unchanged since the last step). The
  link is made on (`t(1)`, `addr(1)`) under the
  default stub, or with `Node::on` on a pair, settings and facts the
  test gives; `Node::with` swaps the facts and asserts that they give
  the link the class and kind it was made with. `Node::heard` makes the
  peer capable as in use, by stepping a `PathClose` from the original
  path's pair that names no path held, without accounting its frame;
  `Node::capable` builds a node and calls it at instant 0, so a held
  candidate is admitted as it is in use. `Node::candidate` reports a
  candidate from configuration, `Node::report` from a source the test
  names, and `Node::unlist` takes a source off one.
  `public` names an Internet-facing address of the peer.
  `Node::account` passes a frame to `Bundle::account` and checks that it
  dropped no slot. `Node::charge` passes a failure to `Bundle::charge`
  and checks that it dropped no slot and that, when it returns
  `Tripped`, the next wake is at or before the call's instant, so the
  poll the shell then makes at once is not early.
  `Node::disabled` makes a node whose bundle runs with multipath
  disabled. `Node::renew_to` passes the call to `Bundle::renew` with the
  pair the link moved to, checks that it dropped no slot and handed none
  out twice, and then follows the new original path and the new link's
  capability probes; `Node::renew` renews at the active path's pair.
  `Node::step` keeps every slot the bundle hands out, returns the outputs
  with each slot replaced by its serial, and checks after every call that
  while the peer is not known to be capable no connection is asked for
  and every send is a capability probe: a `PathProbe` of exactly 27
  bytes on the original path's pair before the call, carrying its
  identifier, `ACTIVE` and no capability bit, sent only when, after the
  call, the bundle holds a candidate that allows one by the shell's own
  reading of the candidates and the facts, and at least the schedule's
  gap after the one before, the gap worked out again in the shell from
  the settings; that the link is reported not capable at most once and
  never after it was reported capable; that nothing is sent and no
  connection asked for by a node with multipath disabled; that every
  connection asked for is to a path held, on a connection-oriented
  transport, with no probe on that path in the same call; that every ack
  answers the call's probe on its pair, is exactly the larger of 27 and
  the smaller of the probe's length and the link MTU less the frame
  overhead, and leaves `EXT` clear; that no probe exceeds its link MTU
  less the frame overhead, is under 27 bytes or sets `EXT`; that an
  address moves only on a probe or an ack; that path policy, under the
  facts at the call, allows every path admitted from a candidate, every
  path a probe created, every path other than the original brought back
  from Dead by carrier or a candidate report, as one it may probe, or by
  the peer's probe, as one that probe may create, every path other than
  the original moved to a new pair, and every probe of a Dead path other
  than the original; that every close names a path
  held before the call by the peer's identifier and does not travel on
  that path; that every slot handed out is
  new and the call dropped none; that no path is released while it is
  active, starting from the path active before the call and following
  each switch in the outputs, except as its transport goes; that every
  switch goes to an acked path; that every discretionary change goes from
  the path active before it, followed by its identifier through the call's
  switches and any move, to another path, both Live after the call, and
  so does every pinned change; that every pinned change goes to a path
  the bundle's pin names after the call, read by the shell's own
  matching of the pin's transport and address; that no Live, acked path
  ranks above the active path after the call by the roles the stub
  gives their transports, normal and preferred above backup and backup
  above never, unless the pin names the active path; that across a call
  that changes the active path, the bundle's `cost` at the call's
  instant, for `Node::cost`, is the same after it as before; that
  an active path is held while an acked path is; that the bundle is
  orphaned at most once over the
  node's life; that a poll made before the bundle's next wake, while the
  facts are unchanged since the last step, gives no output and leaves the
  bundle as it was; and that after the call the
  next wake is `None` or later than the call's instant. `Node::poll`
  polls, and `Node::tick` polls at the next wake. `Node::close` checks
  that every path held is released exactly once. Helpers build the
  peer's messages (`probe_from`, `marked` for a smallest probe with
  `ACTIVE` set or clear, `ack_for`, `close_from`), check probe instants
  against the floor of a path that has stopped answering
  (`floor_breaks`, `free_after`, with `FLOOR_MIN` and `FLOOR_MAX`), make
  a Live
  path (`live_path`) or a node with a second one (`two`), name the
  pairs of the first three transports (`p`, `q`, `r`), step an input
  at an instant (`step`, with `down` for a carrier loss and `gone` for a
  removed transport, and `shut` for the peer's close of a path), name
  the active pair (`active`), and pick the outputs apart (`probe_on`
  gives the one probe on a pair, `sent_closes` the closes sent, `asked`
  the connections asked for). `Log`, `handle` and `run` drive a node
  through its wakes, answering the probes a test chooses at the instant
  they go, and record the probes sent, the connections asked for and
  every state change. `scored` reckons a path's score from its public
  accessors, or none before a number of samples. `Net` answers each probe
  after the round trip a test gives for its instant and pair, or never,
  and its `run` steps a node at each answer's arrival and each wake up to
  an instant, an
  answer first at a tie, and returns every change of active path as a
  `Turn`; `turns` picks the changes out of one call's outputs. Its one test,
  `each_shell_check_fails_on_an_output_that_breaks_it`, shows each check
  firing on a hand-built output that breaks it, and passing one that
  does not.
- `sim.rs`: the two-party simulator (`proto::path::tests::sim::...`).
  `World` runs two shells, A and B, over wires that join one of A's pairs
  to one of B's, each with a seeded one-way delay of 1 to 100 ms in each
  direction and a loss rate, and delivers path messages and data frames
  as a host would: each frame through `Bundle::account`, then a path
  message decoded and stepped. Each node sends a data frame every 100 ms
  and a heartbeat every second on its active path and is polled at its
  next wake. In the uneven shape A has two transports and B one, so B
  holds both its paths on one transport; in the even shape each has two.
  Scripted rules drop one class of datagram (probe, ack, close, data or
  all) in one direction or both on one wire for a window. When a wire
  heals, and while it stays healed, an end that holds no path for it, or
  only one Dead and never acked, is given its candidate again as local
  discovery that dropped the pair and lists it again, so the report is
  fresh and releases the pair if it was held back; the first report at
  the start comes the same way. Neither end starts knowing its peer
  capable: at the start the second wire's candidate goes to A or B by
  the seed, that end sends capability probes on the original wire, the
  first to arrive makes the other end capable and its answer makes the
  first end capable. The other end then learns the second path from a
  probe, so in the uneven shape B sometimes learns it from A's probe from
  a new address on its one transport. A test may instead mark the second
  wire at one end with a transport of another anonymity class, or one
  whose role is never, and give both ends its candidate; a marked wire
  is never given again. Every delay and loss is drawn from the seed and
  a stable key, so a run replays from its seed. After every event it
  checks, beside both shells' own checks: that until an end reports its
  peer capable it sends only probes of 27 bytes on the original wire,
  and reports its peer capable once; that once the original wire is
  healed and an end not yet capable holds a candidate it may probe, both
  ends are capable by the later of that instant and the end's next
  capability probe (read then, and checked against the schedule from the
  probes the world saw) plus a probe timeout and two one-way delays; that
  the end refusing a marked wire never holds a path on it or answers a
  probe on it, and neither end has its path acked or Live; that, from
  the instant both ends are capable, a wire healed for the slowest Dead
  cadence plus a probe timeout and two one-way delays has its path Live
  at both ends; that an end whose Live active path's wire is cut in one
  direction or both switches within three active probe intervals, a
  probe timeout and two one-way delays, when another of its paths is
  Live on a clean wire, the verdict cap standing in place of the probe
  timeout, when larger, for an end whose own sending alone is cut, since
  the peer's data frames still arrive on the wire; that no end is
  orphaned while a wire delivers both ways; that no frame roams a path
  and no path message moves one,
  since no address on a wire changes; and that between two acks of one
  path the difference of their `rx_frames` equals the frames the path's
  wire delivered to that end. Before every step each end is given its
  active wire's score from the wire's own delays as the link cost the
  host measures, and each end is stepped a receiver report every 500 to
  2,500 ms, drawn per end from the seed; a test may give a transport a
  role at either end before the run (`World::role`). Three more oracles
  check selection, each by its own arithmetic and calling nothing in
  `select.rs`: that every discretionary switch goes to a path Live at
  that end without a break for at least the switch dwell, the original
  wire's path Live from instant 0 until it first leaves Live, unless it
  leaves a path of a lower tier by that end's roles (**dwell**); that from
  a step that switches until both the dwell has passed and two reports
  have been stepped after it, `Bundle::cost` gives the cost it gave just
  before that step, and the measured cost afterwards (**hold**); and that
  in a run with no rule and no loss, with no role set or one wire
  preferred at both ends, each end ends on the wire the scores and the
  switch margin make its target, by a deadline counted from the instant
  the second wire turned Live there, having switched once, or never
  switches when the target is the original wire, a run whose deciding
  ratio lies within 0.01 of the margin being exempt (**settle**). Both
  ends run with the draft's settings, or with others a test gives through
  `World::tuned`. The tests run 64 seeds of two simulated minutes each:
  every path proven at both ends of the uneven bundle once healed, the
  switch at both ends when the active wire is cut both ways and when only
  one direction is, with the peer's frames still arriving (these two run
  with `steady`, a margin no two paths reach, so an end leaves its active
  wire only when the wire fails, and returns to it only once it is Live
  again and scores better; the first checks both ends are off the cut wire
  while the cut lasts), the receive counts of each path, a run
  replayed byte for byte from its seed, a wire marked at one end never
  becoming a path there nor proven at either end, each end settling
  without faults on the wire better by the margin or staying (fewer than
  four seeds exempt), a wire preferred at both ends carrying the link
  whenever it scores within the margin, half the seeds preferring the
  original wire and half the second, and the cost held across every
  switch under cuts and flaps, with holds ended by the dwell and others
  by the reports; a test feeds each selection oracle a planted breach
  and shows it fires, and shows the dwell oracle accepts a backup path's
  yield; a run in which both ends move to a preferred second wire and
  return to the original wire once it is preferred instead, which the
  dwell oracle accepts; and 64 seeds of three simulated
  minutes in which probes are dropped on the original wire both ways
  from the start for 25 to 60 seconds, so the first round of capability
  probes goes unanswered, the link is reported not capable once, and
  the backoff's next probe makes both ends capable. With `slow-tests`,
  50 seeds of one simulated hour each of flaps, long outages past the
  Dead grace and loss keep every oracle.
- `stub.rs`: the deployed-peer model (`proto::path::tests::stub::...`).
  `Deployed` is a peer of a release that implements no path message: it
  authenticates every frame of the link and discards a path message
  unanswered. `World` pairs it with one node whose host has a clear
  transport holding the original pair, a clear fixed-Local one, a Tor
  one, one whose role is never and one the node would not dial, and
  drives them from a seed: the peer's heartbeat every 10 seconds on the
  original pair, accounted on the bundle; reports and unlistings of six
  candidates, three that path policy allows and three it refuses, about
  twenty minutes apart; carrier lost on the original's transport for 30
  seconds now and then; and the fixed-Local transport's interface
  leaving and coming back. The node is polled at its next wake. The
  world keeps its own account of the candidate table from its script.
  After every event it checks, beside the shell's own checks, that every
  send is a probe of exactly 27 bytes on the original pair carrying the
  original path's identifier; that none goes while the world's account
  holds no allowed candidate that is not held back; that each goes at
  least the schedule's gap after the one before; that at most twelve go
  in the hour from the first and at most six in any hour from the
  twelfth on; that the node reports no connection, switch, capable peer,
  released or moved path and is never orphaned; that the link is reported
  not capable once, at the timeout of the first round's last probe, and
  never otherwise; and that the original path is never Dead or
  discarded. It runs 8 seeds of two simulated hours each, and with
  `slow-tests` 64 seeds of a simulated day each. A third test shows each
  oracle firing on a planted breach (an ack, a probe on another
  transport, one of 28 bytes or naming another path, one with no
  candidate, two 5 seconds apart, thirteen in the first hour, seven in
  a later one, a report of the link not capable twice, early, late or
  missing, and the original path discarded) and passing a day on the
  draft's schedule and seven probes ten minutes apart, which no
  half-open hour holds.
- `select.rs`: tests for `select.rs` (`proto::path::select::tests::...`):
  a path's score is its ETX times one plus its least round trip over
  100 ms, with none before a round trip is measured; and a choice takes
  the least score among the scored rivals over any unscored one, else
  the least latest round trip, one with none measured last, the lower
  index on every tie, and nothing from an empty field; and it keeps the
  highest tier present, a normal rival over a better-scoring backup one
  and a backup one over a never one, and takes a scored preferred rival
  within the margin of the best, at the margin included, the lower
  score of two such, but not one outside it or one with no score; and
  within the top tier it takes a rival whose link MTU carries a
  `FilterAnnounce` over a better-scoring one whose MTU does not, lets
  the score decide when none does, and keeps a normal rival too small
  for it over a backup one that carries it, a fitting normal rival over
  a preferred one within the margin that does not fit, and a pinned
  rival that does not fit over one that does; and among the scored
  rivals within the margin of the best it takes the one on the fastest
  known medium, a cable before a wireless network before BLE, the lower
  score then the lower index between two of one medium, but not one
  outside the margin, one with no score, or any where either medium is
  unknown, and only after the preferred precedence and the
  `FilterAnnounce`; the frame that carries
  the filter is the encoded `FilterAnnounce` plus the frame overhead,
  1,071 bytes; the best score a preferred rival is held to is the least
  among the scored rivals of the highest tier; a move from a loaded
  cable to a wireless network faster at its best is held while the
  cable is within the margin of it at their best, and not outside it,
  with either medium unknown, from the slower medium, or once the load
  has lasted the horizon; a move to a cable for its medium waits while
  the cable is outside the margin of a loaded wireless network at its
  best, and not within it, once the load has lasted the horizon, or
  while the wireless network has no score over the horizon; and a
  hold on a link's cost lasts, at the dwell's end, until the second
  report, and before it whatever the reports.
- `set.rs`: tests for `set.rs` (`proto::path::set::tests::...`), the set
  of paths to one peer: path identity by (transport, address), the
  per-transport and per-peer limits with Dead paths counted, the one-path
  limit of a BLE binding (FRC-1301 Section 6.5.4), the eviction order
  and which limit an evicted path must relieve, path identifiers, when an
  authentic frame may move an address and what its roam reports
  (nothing, a first bind, the pair the active path left, or a path that
  is not active), the three results of a deliberate rebind, which never
  re-points a path, that discarding a path keeps the active index on its
  path and that discarding the active one leaves none, that only an
  acked path can be made active, that a rule hands
  back a path it discards rather than dropping it, and that no rule drops
  a driver slot it does not hand
  back, checked on sets whose slots count their drops, and what the
  source query (`classify`) answers for the active path in any state, a
  held path before and after an ack, an acked and a never-acked Dead
  path, and a pair not held. The other tests
  run on a set over test-clock instants (`testutil::TestInstant`) with no
  driver state (`()`).
- `verdict.rs`: a probe's verdict under load
  (`proto::path::tests::verdict::...`), driven through `Bundle`'s inputs
  in the shell with every probe on the active path lost from 1 s: with a
  session datagram arriving every 50 ms the probes are counted only at
  the verdict cap from their sending, Suspect at 4.4 s; with heartbeats,
  sender reports and the peer's probes arriving instead, or nothing, at
  the timeout floor, Suspect at 1.8 s; the timeout follows three times the
  largest round trip in the window, capped, while a latest round trip
  above the cap keeps three times it and a sample older than the window
  no longer counts (on `Liveness` directly); and a probe sent after a
  late answer of 900 ms in the window is counted at 2.7 s, not 400 ms.
- `view.rs`: the operator's view of a link's paths
  (`proto::path::tests::view::...`) through `Bundle::view`, driven as
  `choice.rs` drives its tests and with its helpers and `pin.rs`'s `pin`
  and `onto_q`: each path's state, whether it is acked, active and
  pinned, its score and identifier, and which path the peer says it
  sends on, set by the peer's probes and not by this end's active path;
  a pin shown in force exactly while the link is on a path it names,
  checked after every step through a carrier loss, the pin's suspension
  and its return, and gone once lifted; and the cost shown held from a
  change through two reports within the dwell, and no longer at an
  instant past the dwell with no step since, while `holding` is still
  true.
- `wire.rs`: tests for `wire.rs` (`proto::path::wire::tests::...`):
  each path message against golden bytes written by hand from the
  multipath v1 draft's tables, round trips, short messages, reserved
  bits, padding, the ack length rule (in transport MTU, less the
  established frame's overhead) and the extension block's rejection
  cases.
