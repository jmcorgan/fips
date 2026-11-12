# core/src/proto/path

The paths a node holds to one peer and the rules for holding them, from
the multipath v1 draft (Sections 5.1, 5.3, 5.5 and 5.6, and Appendix A),
path policy, which keeps a link's paths to the transports it may use
(Section 5.5), the candidates the host reports for a peer and the ones
held back after a discard (Sections 5.4 and 5.6), the capability
probes that learn whether the peer implements multipath (Section 5.2), the
codec of the path messages (`PathProbe`, `PathAck` and `PathClose`) that
prove them (Sections 7.1 to 7.5), the settings the paths of a link are run
with, and `Bundle`, the machine of one link's paths, which runs the probe
exchange that proves them (Section 5.1), tracks each path's liveness
(Section 5.6), keeps the link on its best remaining path when the
active one fails or goes (Section 5.7), tells the peer when one of
its paths goes away (Section 5.8), counts each path's authentication
failures (Section 5.3), has a connection opened to a candidate on a
connection-oriented transport before probing it, and with multipath
disabled says nothing about paths (Section 8.2).

The root crate's peer code holds one `Bundle` for each active peer, and
its node code steps it and acts on what it decides.

## Files

- `candidate.rs`: `Candidates`, a link's candidate table, with `Entry`
  and `Sources`: up to `PATH_MAX_PER_PEER` (8) pairs in a fixed array,
  each with the sources that list it (configuration, Nostr, local
  discovery, an address the peer was heard from, an operator's request),
  whether it is held back, when it was last reported, and the rule that
  refused admitting it at its last attempt, which a poll reads to offer
  it again (`mark` records it; holding an entry back clears it). A
  report from a
  source that already lists the pair is a repeat and changes only that
  stamp; any other report, and every request, is fresh and releases the
  entry. An entry is forgotten when its last source unlists it, unless it
  is held back. `hold` holds back a discarded path's pair, entering it
  with no source if it has no entry; `absent` holds back every entry on a
  transport whose interface left; `release` frees a transport's held-back
  entries and says which; `prune` then forgets those of them no source
  lists that were not admitted; `forget` drops a removed transport's. A
  full table replaces a held-back entry no source lists, then the least
  recently reported entry that is neither held back nor held as a path,
  and otherwise drops the report; it never replaces a path or a
  held-back entry some source lists, whose next repeat would otherwise
  count as fresh. Nothing in it allocates. Its accessors are public and
  read-only; what changes it is visible only inside this module.
- `capable.rs`: `Capability`, a link's record of capability probes
  while its peer is not known to be capable: how many went, the one
  outstanding with the instant it goes unanswered, when the next may go,
  and whether the first round was reported unanswered. `gap` is the
  schedule: `budget` (3) probes share `span` (30 s), then the gap starts
  at `span` and doubles after each probe up to `cap` (10 minutes), so the
  probes go at 0, 10, 20, 50, 110, 230, 470 and 950 seconds and every 10
  minutes after, twelve in the first hour and six in each hour after.
  One is outstanding at a time; an answer matches it only by our
  `path_id` and its `probe_id`, and only before its timeout; `expire`
  reports the first round unanswered once, when the `budget`-th probe
  times out. The count never starts again on a link. Its accessors are
  public and read-only; what changes it is visible only inside this
  module.
- `live.rs`: `Liveness`, one path's outstanding probes, what their answers
  measured and the frames received on it: the ring of up to `RING` (8) probes
  in send order, each with the instant it goes unanswered; the last four
  probes that timed out, so a late answer still gives a round trip; the path's
  `probe_id` sequence, from which a capability probe held outside the ring
  also takes its identifier (`take_id`), to be kept with the timed-out probes
  once it times out or the peer turns capable (`lapse`); the count of
  unanswered probes in a row, where a timeout counts only if no later probe
  was answered in time; when the next probe is due and whether one is asked
  for at once; whether the peer marks the path `ACTIVE`; the latest round trip
  and the window of samples its minimum and maximum are taken over, its least
  round trip over the horizon (`base_rtt`, kept in eight spans, each the
  horizon over six wide, a span dropped once its latest sample is older than
  the horizon), the smoothed ETX, the proven MTU, and the frames and bytes
  received on the path (modulo 2^32, the `rx_frames` and `rx_bytes` its acks
  report) with when the latest arrived and when the latest session datagram
  arrived, when the path last left Live, and the count of frames that failed
  to authenticate on it since the latest authentic one, with the instant of a
  trip not yet applied, and whether the path has the connection its probes
  need, needs one, or has one being opened. It also holds the path's silence
  clock, the send instant of the earliest probe since the latest matching
  answer (`quiet`), and, once the path has stopped answering, its stop: the
  instant from which its next probe on its own cadence may go, the least gap
  after that one, doubling from `PATH_DEAD_PROBE_INTERVAL_MIN` to
  `PATH_DEAD_PROBE_INTERVAL_MAX` with each probe counted (`halt`, `held`,
  `spend`), or, for a path that was our active path when it last left Live
  (`left`) or is at the stop, held at `PATH_DEAD_PROBE_INTERVAL_MIN` until
  `PATH_DEAD_RECHECK_SPAN` after its silence clock started (`recheck`), and
  whether the latest slot counted went to a connection, which its opening
  settles (`owe`, `rebase`); `resume` ends the stop. `Answer::matching` says
  whether an answer is a matching one: one in time is; a late one is not,
  anywhere (draft Section 5.6), so it gives a round trip and does not end a
  stop. For the size of a Probing or Dead path's probes it keeps the first
  `probe_id` of the path's current state, whether a padded probe sent in that
  state has timed out, and the length of the latest probe sent in it, all
  started again by `fresh` at each change of state; `size` gives the next
  probe's length: padded to the link MTU until a padded probe of the state has
  timed out, and from then on the next step of a ladder after the probe before
  (the link MTU, three quarters of it, half of it, the smallest size, and the
  link MTU again). A probe still outstanding from the state before does not
  count toward that. It keeps the upward search for the size a Live path
  carries, in a small record of `u16` sizes: the outstanding search probe,
  held outside the ring, the smallest size lost and the instant the next may
  go (`seek_size`, `seek_send`, `seek_answer`, `seek_proved`, `seek_judge`).
  The search tries the link MTU first, then halfway between the size proven
  and the smallest lost, ends within `SEEK_STEP` (32 bytes) and starts again
  `SEEK_RAISE` (ten minutes) later; a search probe is lost only once its
  timeout has passed and a probe sent after it has been answered in time, and
  it is no miss and no ETX sample. `fresh` starts the search afresh. `prove`
  says whether the proven MTU changed. It also keeps the first `probe_id` sent
  since the path last left Dead (`thaw`): an earlier probe still outstanding
  then times out counting toward no unanswered count, and the mark is dropped
  once no such probe is outstanding. It records whether a beacon has brought a
  probe forward in the current state (`beaconed`), which `fresh` clears at
  every change of state. Fixed arrays only, so
  nothing in it allocates. Its accessors are public and read-only; what
  changes it is visible only inside this module.
- `machine.rs`: `Bundle<C, E, D>`, the machine of one link's paths, over
  the host's clock `C`, entropy source `E` and driver slot `D`. `new`
  builds the link's set around its original path, Live, acked and active,
  and fixes the link's `Scope`, its class and kind, from the original
  pair through the host's facts (`scope` reads it).
  `step` takes one `Input` at an instant and returns the `Output`s the
  shell executes front to back. `close` hands back every path's slot.
  `renew` starts the link again at the pair FMP v1 moved it to, as a won
  crossed handshake does (Sections 5.2 and 5.4): a path held at that
  pair, active or not, becomes the new link's original path under a new
  `path_id`, Live, acked and active, keeping its slot and its count of
  failed frames, and is not released, since the link now sends on its
  connection; otherwise a new path at the pair, with a slot of its own,
  does; the peer is no longer known to be capable, the candidates, the
  capability record and a discretionary change under way are dropped, the
  operator's pin and the hold on the link's cost are kept, the scope is
  read again, and every path that does not stay comes back in an
  `Output::Released`. Every path of the old link, the one that stays
  included, is reported ending in an `Output::State` with `next: None`,
  and the new original path beginning with `from: None`, each for
  `Why::Renewed`, so that no `path_id` changes unlogged.
  `driver_mut` lends the host one path's slot, and `paths_mut`, only in
  test builds and under the `test-hooks` feature,
  the set itself, for the root crate's tests of the set's rules. The
  exchange: a candidate admitted becomes a Probing path, probed at once
  and padded to the link MTU. A Probing or Dead path's probes are padded
  until a padded one of its current state goes unanswered, and from then
  on step down the ladder, until its state changes (padding is local,
  draft Section 5.1): a hop narrower than our link MTU, or a receiver
  whose buffer is smaller, drops every probe over its size, and the
  first rung answered proves that size; a smallest one answered proves
  the path though no MTU, so such a path is no worse off than a link of
  one path between two nodes of different MTUs. On a Live path on a
  connectionless transport whose proven size lies above the smallest and
  below the link MTU, a padded search probe goes just ahead of a probe
  at its cadence, at most once per standby interval and only while no
  probe of the path is unanswered, and an answer to it raises the size
  proven; no search runs on a connection-oriented transport, where an
  oversized probe closes the connection. Each change of the size
  proven, up or down, is reported in an `Output::Proven`, as the largest
  frame in bytes, for the shell to apply. A received probe of at least 27 bytes
  finds its path by the peer's `path_id` on its transport, then by its
  pair, and otherwise creates a Probing path within the limits, and is
  answered on its pair with an ack padded to the smaller of the probe and
  the link MTU; an ack matches on (`echo_path_id`, `probe_id`) on any
  transport, and only a match learns the peer's `path_id`, samples a round
  trip, proves an MTU and makes the path Live; a `PathClose` names our
  `path_id` and makes a Live or Suspect path Dead. Any path message makes
  the peer capable, and before that nothing but capability probes is
  sent. While the link holds only its original path no path message
  moves it, also once a second path has been discarded. With two or more
  paths, or one path that is not the original, a path's address moves
  only on its own probe or matching ack, on its own transport, from a
  pair no other path holds, and its old slot goes back to the host in
  `Output::Moved`. `account` takes every
  authentic frame of the link after the replay check, with the whole FMP
  frame's length and its link message type: while the link holds only
  its original path it applies the single-path roam of `PathSet::roam` to
  a frame that is not a path message and returns its result in an
  `Account` (no path message roams while multipath is enabled, and no
  frame once the original path is not the link's one path, draft Section
  5.3; a bundle with multipath disabled roams its one path on every
  frame, path messages included, since FMP v1 governs every link of such
  a node, Sections 8.2 and 9.2); it attributes the
  frame to the path of its pair or to none and counts it there, and the
  step that takes a probe or a matched ack moves the frame to the path
  the message concerns when that is another (Section 5.1); and it
  tracks the peer's active path, the path of its latest link
  message that is neither a session datagram nor a path message (draft
  Section 5.12). The `Account`'s sample flag is set on a link of one
  path, and otherwise only for a frame on the peer's active path. A path
  message's frame is accounted before the message is stepped, so an ack's
  receive counts include the probe it answers. A path released while it
  is the peer's active path comes back with `keep` set, so the host
  keeps a connection the peer still sends on (Section 5.8), and so does
  every path of a link whose peer is not known to be capable: such a
  link keeps every connection, as FMP v1 does (Section 9.2).
  Liveness (Section 5.6): a step runs the expiry of every probe whose
  timeout passed before the step's instant, the capability probe's among
  them, then the peer
  turning capable on a path message, then the input, then the expiry of
  every probe due by the instant, then the choice of the active path,
  then the grace of Dead paths, then the capability probe and the probes
  due, so an answer after its
  probe's timeout is late whether or not the host polled between. The
  timeout, a local choice, is the largest of 400 ms, three times the
  latest round trip, and three times the largest round trip in the window
  capped at the verdict cap (`verdict_cap`, 3 s). A probe whose timeout
  passes after a session datagram has arrived on its path since it was
  sent is not judged yet: it becomes due at the cap from its sending, and
  is judged then as any other. The peer's traffic arriving shows the path
  still carries data and the probe may be queued behind it; heartbeats,
  reports and path messages hold no verdict, so on an idle link a failure
  of this node's own direction is found as fast as before, and under
  load at most the cap after the probe went. A Live
  or Suspect path keeps up to eight probes outstanding, a Probing or Dead
  path one. Our active path and a path the peer marks `ACTIVE` are probed
  every 200 ms, a standby every second, a Probing path from 200 ms
  doubling to the heartbeat interval, and an acked Dead path from one
  second doubling to 30 seconds, which at the defaults meets the floor
  below exactly, except that a Dead path re-checked after it carried the
  link is probed at the floor's gap, every second through the span and
  doubling after it; on a connection-oriented transport it goes at the
  size it has proven where it has proven one, not on the ladder, and on a
  connectionless one it keeps the ladder, so a path narrower after its
  outage is still found. Each probe schedules the next at the
  interval of the moment it went, and the send phase brings a path's next
  probe to no later than one interval of its cadence, so a path answered
  back to Live, made our active path or marked `ACTIVE` by the peer is
  probed at its new cadence from then on. A link whose one path is Live
  is not probed, nor
  a Dead path never acked, nor any path before the peer is capable. Three
  unanswered probes in a row make a Live path Suspect, ten more retire it
  to Dead, and eight make a Probing path Dead; only a Live path's
  timeouts are ETX losses, and a late answer gives a round trip and
  nothing else. Carrier loss and an unreachable send make a Live path
  Suspect; carrier's return, a fresh candidate report of the pair, a
  fresh report from local discovery on its transport or the peer's probe
  brings a Dead path back to Probing, where path policy allows: probed
  at once when the peer's probe brought it back, and otherwise with its
  first probe held to the floor below. Every change of
  state starts the unanswered count again, entering Dead gives up the
  outstanding probes, and a probe still outstanding when a path leaves
  Dead counts as no miss when it times out, though an answer to it in
  time still matches. The peer's `ACTIVE` turning off on a path asks for
  one probe at once, which is dropped if the ring is full, and is counted
  toward the eight on a Probing path; no such request outlives the step.
  A Probing path sends no more than eight probes in all, on its cadence or
  at once: one asked for at once after the eighth is dropped, and the
  path becomes Dead when the eighth times out. A Dead path that is not active is discarded once
  `PATH_DEAD_GRACE` has passed, if it was never acked or a path is Live.
  A path that is not Probing stops answering when it becomes Dead, or
  once `PATH_SILENCE_MAX` (60 s) has passed since the earliest probe no
  matching answer has followed, whichever is sooner; while stopped, its
  probes on its own cadence, in whatever state, wait at least 1 s after
  the stop and after the first, and each later gap at least doubles, up
  to 30 s (`PATH_DEAD_PROBE_INTERVAL_MIN` and `_MAX`, constants, not
  `Config::dead_interval`). A path that was our active path when it left
  Live, or is at the stop, is re-checked first: its gaps stay 1 s until
  30 s after it went silent (`PATH_DEAD_RECHECK_SPAN`, a constant), and
  double from there, so a silent outage of the path that carried the
  link is found within about a second of its end. The draft's floor
  doubles on every path; this span is a bound of an amendment to Section
  5.6 not yet in the draft. A stop takes the re-check once each time the
  path leaves Live. A connection asked for in place of such a
  probe counts as one, and when it opens the next probe waits that
  slot's gap from the opening. The probe at once when the peer's probe
  brings a Dead path back, those Section 5.7 requires at once, the early
  probe when the peer clears `ACTIVE` and the probe sent when a
  connection opens are neither held nor counted. An answer in time ends
  the stop, as does the peer's probe bringing a Dead path back, which
  starts the discovery probes afresh; carrier's return or finding the
  peer again keeps the stop over the discovery probes that follow, the
  revival's own first among them, each held and counted, and a late
  answer or the peer's probe on a path it does not bring back does not
  end it. `pace` never brings a held probe
  earlier than the floor's instant, and the send phase schedules a
  counted probe's next no sooner than it.
  `next_wake` is the earliest instant a poll has work: a trip recorded by
  `charge`, a probe's timeout, a probe due on a path with room for it, a
  grace ending in a discard, the end of a discretionary change's switch
  dwell, or, before the peer is capable, the capability probe's timeout
  or, while a candidate allowed one at the last step, the next
  capability probe.
  Capability (Section 5.2): until the peer is capable the bundle sends
  only capability probes, in the send phase before any other: on the
  original path's current pair, exactly 27 bytes, carrying the original
  path's identifier, `ACTIVE` and no capability bit, with a `probe_id`
  of its sequence, at the schedule of `capable.rs`, and only while the
  gate is open: some candidate is not held back, its pair is not held as
  a path, and the rules allow probing it, read from the facts at each
  send phase. The gate's result is kept (`capability` reads the record)
  for `next_wake`, which takes no facts; a roam of the original path in
  `account` reopens it, since it may free a candidate's pair, and a wake
  that finds it closed sends nothing. While the gate is closed nothing
  goes and nothing wakes for it, and when it reopens the next goes at
  once if its time has passed. A capability probe is held in the record,
  not the original path's ring, so its timeout never counts toward that
  path's liveness; once it times out it is kept with the path's timed-out
  probes. When the `budget`-th times out unanswered the bundle emits
  `Output::NotCapable` once. An ack matching the outstanding probe makes
  the peer capable, learns its identifier for the original path, samples
  a round trip (no loss sample, no MTU) and makes a Suspect original
  path Live; a late one gives a round trip and nothing else. Any path
  message makes the peer capable before its input is taken: it emits
  `Capable` once and admits every candidate the rules allow, and a
  capability probe still outstanding after the input is kept with the
  timed-out probes, so `NotCapable` never follows `Capable`. A new link
  starts a new record.
  The active path (Section 5.7): a Suspect active path gives way to the
  best Live path, and otherwise stays active, never swapped for another
  Suspect path; a Dead active path, or one probed again after Dead,
  gives way to the best Live path, else the best acked Suspect path, and
  otherwise stays active, so data and heartbeats still go out on it. The
  best Live path is the one `select.rs` ranks first among the Live,
  acked paths other than the active one: among those the operator's pin
  names, while it names any, and then those on transports of the
  highest tier present, by the role the facts give each (`Normal` and
  `Preferred` above `Backup`, `Backup` above `Never`), and then those
  whose link MTU, as the facts give it, or on a connectionless
  transport the smaller size the path is proven to carry, takes the
  1,071-byte frame of a `FilterAnnounce` (Section 5.11), while any
  does, the least score
  among those with `min_samples` round-trip samples, unless a `Preferred`
  one scores within `switch_margin` times that least, when the least
  scoring such path; and then, among the scored paths within
  `switch_margin` times the least (only the `Preferred` ones when a
  `Preferred` one was taken), the one on the fastest known medium, a
  cable before a wireless network before BLE, when its medium is faster
  than that of the path taken so far and both are known (the facts give
  each path's medium; an unknown one leaves the choice to the score);
  else, when none has that many samples, the least
  latest round trip, one with none measured last. The best
  acked Suspect path has the least latest round trip, one with none
  measured last. Every tie goes to the lower index. Each change is an
  `Output::Switched` with `Switch::Mandatory`; only an acked path is
  ever chosen. When the active path became Suspect or Dead or was
  discarded in the step and no path is Live, every acked Dead path is
  probed at once, where the probe rules allow it, and every acked path
  being probed again after Dead, whatever brought it back, within the
  discovery limit; and when the active
  path was discarded and no path is Live, the path made active in its
  place is probed at once also when it is Suspect or being probed again
  after Dead (Section 5.7). A Live active path may give way by a
  discretionary change (`Switch::Discretionary`) to the path
  `select.rs` ranks first among all the Live, acked paths, when that is
  another. When the
  operator's pin names it and not the active path, the link moves to it
  at once (`Switch::Pinned`), whatever its tier and samples. When its
  tier is higher than the active path's, the link moves to it at once,
  whatever its samples. Otherwise, when it has `min_samples` samples and
  either it carries a `FilterAnnounce` and the active path cannot, or it
  is `Preferred` and the active path is not, or it runs over a known
  medium faster than the active path's, also known, or the active path
  also has them and scores more than `switch_margin` times it, or more
  than it at all when it is the path the latest change of active path
  left and that change was mandatory, or the active path has them and
  scores more than `switch_margin` times the best score among the paths
  `select.rs` ranks, so it holds the link by no precedence (the path
  ranked first may hold its place by the preferred precedence or by its
  medium), a switch dwell starts, keyed by the path's identifier, and
  the link moves to it at the first step at or after `switch_dwell` from
  then at which all of that still holds. The return needs no margin
  because the path the link fled to may score within it of the path left
  only for a while: under load its window still holds the round trips it
  measured idle, until its own loaded ones fill it, about 6.4 s at the
  active cadence. Any of those last three, a
  change on score, is held (`select::held`) while the active path is the
  faster of the two at its least round trip over the horizon (`horizon`,
  60 s), unless the path ranked first also beats the active path's score
  from that least round trip by the margin: load on the active path
  raises its least round trip over the window within seconds, but over
  the horizon only once the load has lasted it, so the load alone does
  not hand the link to a path slower at its best for a horizon. A change
  to a path faster at its best is not held, so a return to a path left
  by a mandatory change keeps its timing, unless the active path runs
  over a known medium faster than the other's and its score over the
  horizon is within `switch_margin` times the other's: idle, the active
  path would take the link back on its medium one dwell later, so load
  that followed the link would move it back and forth each dwell. A
  change for a faster medium is held the same way (`select::waits`)
  while the path ranked first scores more than `switch_margin` times
  the active path's score over the horizon: idle, the two scores of the
  active path agree and only the margin of the best decides, but load
  on a wireless network faster at its best than a cable outside the
  margin of it ranks the cable first within seconds, and the cable does
  not take the link until the load has lasted the horizon, since the
  wireless network would take it back once the load followed.
  The dwell starts again when the path ranked first changes, and ends at
  any step at which that does not hold, at any step at which the
  active path is not Live, and at every change of active path. Its end
  is a wake. A path of the active path's role, which carries a
  `FilterAnnounce` exactly when the active path does, never takes its
  place by scoring the same as it. While the active path is too small
  for the filter, the node cannot send its filter to the peer
  at all, so within a tier carrying it outranks both the preferred
  precedence and the score; a backup path that carries it still waits
  behind a normal one that does not.
  The pin (`Input::Pin`, read by `pin`) names a transport and,
  optionally, the peer's address on it, and replaces any pin before it.
  It is in force while a Live, acked path it names is held, and
  suspended otherwise, when the active path is chosen as with no pin; a
  pin naming nothing held is kept, suspended, until a path it names
  turns Live. While it is in force it comes before tiers, the
  `FilterAnnounce` and scores, so the link moves to a path it names at
  once and stays there; a pin of a
  transport chooses among that transport's paths by the usual rules.
  When a pinned active path fails, the mandatory change goes to another
  Live path the pin names, else as with no pin. It ends on
  `Input::Unpin`, after which a change by the margin waits for the
  dwell, and when its transport is removed or its interface leaves,
  although the interface's candidates are held back for its return. It
  also ends with the bundle: a restart or replacement of the peer that
  builds a new link builds a new bundle, which holds no pin, and the
  host steps `Input::Unpin` when a restart keeps the link (one this node
  learns of during its own rekey). A crossed handshake settled by address
  order, at either node, and whether or not one dial is this node's own
  later dial to a peer it holds, keeps the pin; the node that moves
  renews the bundle, which keeps it. That holds also where the peer had
  dropped the peering and made a new one from that later dial, which the
  dialer cannot tell from a crossed handshake.
  The cost hold is this implementation's choice: the draft leaves the
  link cost of a bundle to the node (Section 5.12, its note). `cost`
  gives the link's cost for the spanning tree at an instant, from the
  cost the host measures then, which every call passes in `Env::cost`.
  Every change of active path, of any of the four `Switch` reasons,
  holds the cost read at the start of its step, before any phase: the
  cost the host measured, or the cost of a hold still in force, which a
  change during a hold thus keeps. The hold lasts until the switch
  dwell has passed since the change and two `Input::Report`s have been
  stepped after it; a report
  counts only toward a hold in force when its input phase runs, so a
  report stepped with the change counts toward the hold before it and
  not the new one, and a report with no hold in force changes nothing.
  The end of a hold is not a wake: nothing is done there, and `cost`
  reads the hold against the instant it is given. `holding` says whether
  a hold is in force or has ended and not yet been found so: a step
  clears a hold it finds ended before any phase, except a `Poll` made
  before `next_wake`, which with the facts unchanged changes nothing and
  leaves it for the next step. While `holding` is false `cost` returns the cost it is given, so
  the host reads no clock to ask; a disabled bundle never holds.
  The operator's view: `view` gives a `View` of the link at the instant
  it is given, for the node's control socket and fipstop. It shows
  whether multipath is enabled and the peer capable, whether the cost is
  held at that instant, the pin as a `PinView` with whether it is in
  force, and one `PathView` per path in the set's order: its pair,
  identifier and state, whether it is active, acked, pinned and the path
  the peer's latest probe or matched ack on it said the peer sends on,
  its latest and least round trips, samples, ETX and score, its proven
  MTU, its frames and bytes, the age of its latest authentic frame at
  that instant, and its unanswered probes and authentication failures.
  The pin is in force when it names a path that `contends`, the same
  test of a Live, acked path the choice of active path applies, so the
  view cannot show a pin in force that selection ignores. `view` reads
  nothing but `&self` and the instant it is given.
  A removed transport, or one whose interface left (`Input::Removed`,
  `Input::Present` with `present` false), has every path on it discarded
  and released at once, the active path included; the interface's return
  is carrier's return. A removed transport's candidates are forgotten; an
  absent interface's are held back, the discarded pairs among them. With
  the active path discarded, the best Live
  path takes its place, else the best acked Suspect path, else the acked
  path most recently Live (`Switch::Handover`). With no original or acked
  path left, the bundle emits `Output::Orphaned` once and from then on
  answers no input, has no wake, and attributes and roams no frame in
  `account`; the shell removes the peer and calls `close`. A Dead path's
  grace runs after the choice, so a Dead active path that gives way to a
  path turned Live is discarded in that step once its grace has passed.
  Closing a path (Section 5.8): when a transport is removed, its
  interface leaves (reason `InterfaceGone`) or it loses carrier
  (`CarrierLost`), the input phase first sends a `PathClose` for each
  path on it whose identifier the peer gave us, naming that identifier,
  all on our active path when it is Live and on another transport, else
  on the Live path of lowest index on another transport. With no such
  path, or before the peer is capable, none is sent, and none ever goes
  on a path of the transport closing.
  Authentication failures (Section 5.3): `charge` takes every frame of
  the link that fails to authenticate, with its pair, and returns a
  `Charge`. It counts the failure only on the original path or a path
  acked in this link, in any state (the `Proven` answer of `classify`);
  any other frame counts toward nothing (`Nothing`). An authentic frame
  through `account` sets its path's count back to zero, and `authentic`
  does the same for an authentic frame the shell does not account, such
  as one too short to carry a message; a pair no path holds resets none.
  When a Live or Suspect path's count reaches `AUTH_FAIL_LIMIT` (20)
  while another path is Live or acked Suspect, `charge` records a trip
  and returns `Tripped`; the next step applies it first, before its
  input, making the path Dead as of the failure (`Why::AuthLimit`) and
  then choosing the active path as usual, and drops it if the path or
  the others have changed so that it no longer may trip. Until that
  step `next_wake` is at or before the failure, so the poll the shell
  makes at once is not early. Reaching the limit in any other case
  returns `Warn` and changes nothing; counts past the limit return
  `Counted`.
  Connections: a path admitted from a candidate on a transport the host
  says is connection-oriented (`Facts::oriented`) needs a connection
  before it is probed. Where its probe would go, the send phase emits
  `Output::Connect` in its place, and nothing is probed on the path, nor
  timed for it, while the connection is pending. `Input::Connected` with
  `ok` probes the path at once; without `ok` it counts as one unanswered
  discovery probe, the next `Connect` waits for the discovery interval,
  and the eighth failure in a row makes the path Dead (`Why::Connect`).
  Every other path, the original and one a probe created included, has
  its connection already.
  Beacons: `Input::Beacon` reports an unauthenticated beacon heard from
  a pair. A path held there that is Probing and never acked, with none
  of its probes outstanding and its next not yet due, has that probe,
  or the connection it needs, due now, once each time it enters
  Probing. It is not asked for at once: it keeps the Probing cap of one
  outstanding, counts toward the eight, and waits for the floor of a
  path that has stopped answering, so beacons add no probe to a Probing
  episode and move at most one of them earlier. A beacon anywhere else
  changes nothing, a beacon never makes the peer capable, and a bundle
  with multipath disabled takes it as a poll. The root crate's node
  steps it for an anonymous beacon at a capable linked peer's Probing
  pair, in place of a dial.
  Candidates (Sections 5.4, the note, and 5.6): every `Input::Candidate`
  is held in the table (`candidates` reads it) whatever the peer's
  capability and the rules; a full table refuses it with
  `Refusal::Table`. `Input::Unlisted` takes a source off a pair. A pair is
  admitted only while the peer is capable, its entry is not held back,
  it is not held as a path and the rules allow probing it, and only on a
  fresh report of it, its release, the peer turning capable, when every
  held candidate is tried in slot order before the input that turned it
  is taken, or a poll (below). A repeat or room freed by a discard admits
  nothing. A poll offers again, in slot order, each held candidate a rule
  refused at its last attempt, so a change in the facts admits it at the
  next poll; the poll reports a `Refusal::Rule` only when the refusing
  rule differs from the one last reported for it, and a candidate it
  finds no room for is refused once with `Refusal::Full` and then waits
  for its next trigger. Every discard holds back its pair: the grace,
  the eviction to make room, and an interface leaving. A held-back pair
  is released by carrier's return or the interface's on its transport, a
  fresh report of it, or a fresh report from local discovery on its
  transport, which is the peer found again and also brings back every
  Dead path there. A released pair no source lists is offered once and
  then forgotten unless it was admitted. A candidate never moves a path,
  the active one included.
  Path policy (Section 5.5), read from the facts at each check through
  `rules.rs`: a candidate of a capable peer is admitted only where the
  node may probe it (class, kind unless `Config::mix_kinds`, role and
  dial), and is otherwise refused with `Refusal::Rule`, naming the rule;
  a probe that would create a path is answered only where a path may be
  created (class, kind, role and accept), and a probe or ack that would
  move a path other than the original to a new address only where the
  path may run there (class, kind and role). A refused probe still makes
  the peer capable, but is not answered and learns or moves nothing; a
  refused move by an ack is skipped and the rest of the match stands. A
  probe that finds a path at its own pair is answered whatever the
  rules, so the peer can prove a path this node only dials. A Dead path
  other than the original is probed again, on carrier's return, on a
  candidate report of its pair, at the Dead cadence, when the active
  path leaves Live with nothing Live, or when asked for at once
  otherwise, only where the node may probe it as a candidate. At the
  cadence a refused probe is put off by an interval, unsent and not
  counted; one refused at once is dropped. The peer's probe brings a
  Dead path other than the original back to Probing only where a probe
  from its pair could create a path (class, kind, role and accept), so
  a path on a transport the node accepts on but does not dial comes
  back on it. Elsewhere a probe that finds a held Dead path is answered
  and leaves it Dead, while one that finds no path at its pair is
  refused. A peer the ACL denies is one the node would dial and
  accept on no transport, so its Dead paths are neither probed nor
  brought back; its Live and Suspect paths are probed until they fail.
  The original path is the link and is never refused, a denied peer's
  included.
  Multipath disabled (`Config::enabled` false, Section 8.2): a step takes
  a candidate, its unlisting, a path message or a connection report as a
  poll, so it is not answered, is not held, makes no path and does not
  make the peer capable, and the peer holds this node as one that does
  not implement multipath. No path is probed, no `PathClose` sent, no
  connection asked for, no capability probe sent and no pair held back,
  so `next_wake` is `None`. `account`,
  `charge`, carrier, an unreachable send, presence, removal, the pin, a
  receiver report and `Orphaned` behave as when enabled, on the link's
  one path, which never changes, so no cost is held.
- `mod.rs`: declares the files and the tests, and re-exports the public
  items of `candidate`, `capable`, `live`, `machine` (`Bundle`,
  `Account`, `Charge`, and the operator's `View`, `PinView` and
  `PathView`), `params` (with `RING` and the three bounds
  `PATH_SILENCE_MAX`, `PATH_DEAD_PROBE_INTERVAL_MIN` and
  `PATH_DEAD_PROBE_INTERVAL_MAX`) and `set`.
  It defines the machine's interface: `Input` (a poll, a candidate with
  its `Source`, a source no longer listing one, the three path messages,
  carrier, an unreachable send, an interface leaving or returning, a
  removed transport, a connection settling, an operator's pin and its
  lifting, and a receiver report),
  `Output` (with `Output::NotCapable`, and `Output::Proven`, a change of
  the size a path is proven to carry), `Outputs`, `Env` (the facts and
  the link's cost the host measures), the `Facts`
  trait the host answers (link MTU and medium, per transport and peer
  address, the medium `Medium::Unknown` where the host cannot tell it;
  whether it is connection-oriented, anonymity class, fixed kind if
  any, role, and whether the node would accept or dial the peer, per
  transport),
  `PathRef`, `Why`, `Switch`, `Refusal` (with
  `Refusal::Rule` and `Refusal::Table`), `Source`, `Class`, the
  anonymity class, `Kind`, local or
  Internet, and `Role`: a `Never` transport takes no new path, and the
  four values rank a link's Live paths in choosing the active one. It
  re-exports `Rule` and `Scope` from `rules` and `Pin` from `select`,
  and holds the module-wide `deny` of wildcard match arms.
- `params.rs`: `Config`, the settings of a link's path machine, with
  `Config::draft` giving the draft's values (Appendix A), and for the
  verdict cap and the horizon, which the draft leaves to the node, 3 s and
  60 s; `Params`, the
  validated settings and the round-trip window derived from them; and
  `ParamsError`. `Params::new` is the only way to a `Params`: it refuses
  zero for every interval and count, a switch margin that is not a
  finite number of at least 1.0, and a ring of more than `RING` (8)
  outstanding probes. `Bundle` holds one and reads the round-trip window
  from it. The draft's bounds on a path that has stopped answering are
  constants beside `RING`, not settings, since no node chooses a bound:
  `PATH_SILENCE_MAX` (60 s), `PATH_DEAD_PROBE_INTERVAL_MIN` (1 s) and
  `PATH_DEAD_PROBE_INTERVAL_MAX` (30 s). `Config::dead_interval` is the
  node's own cap on an acked Dead path's cadence, not that bound.
- `rules.rs`: path policy's checks, private to the module: `scope`, the
  kind of a peer's address (loopback, link-local, private and
  unique-local addresses, and IPv4-mapped ones of those, are local;
  every other address, a host name or a MAC address included, is
  Internet); `kind`, a transport's fixed kind, else its address's scope;
  `link`, a link's `Scope` from its original pair; and the checks
  `moves` (class, kind unless mixed, role), `probe` (those and dial) and
  `admit` (those and accept), each returning the `Rule` that refused,
  and `Check`, their shape, for the machine's `holds`, which applies
  one of them to a held path.
  They read the facts and keep nothing, and allocate nothing. No
  identifier in the module may be `policy` or `Policy`: the rekey
  module's scan of core sources bans both.
- `select.rs`: path selection, private to the module (Section 5.7 and
  its note, and the note of Section 5.5): `score`, a path's score, the
  `quality_index` of its ETX and its least round trip in milliseconds,
  lower being better, the one the spanning tree costs a link by; `tier`,
  the rank of a transport's role, 2 for `Normal` and `Preferred`, 1 for
  `Backup` and 0 for `Never`; `Pin`, an operator's pin of a transport
  and optionally the peer's address on it, public and re-exported, whose
  `names` says whether it names a pair; `Rival`, a Live, acked path a
  choice may take, with its score once it has `min_samples` round-trip
  samples, its latest round trip, its tier, whether its role is
  `Preferred`, whether the pin names it, whether its link MTU carries
  a `FilterAnnounce` (`fits`) and its medium; `quicker`, whether one
  known medium is faster than another, a cable before a wireless network
  before BLE; `held`, whether a change on score waits under load, and
  `waits`, whether a change for a faster medium does, while the path
  taken scores outside the margin of the active path's score over the
  horizon;
  `FILTER_FRAME`, the 1,071 bytes of the
  frame that carries a `FilterAnnounce`, the frame overhead and the
  encoded message with its filter sized by the shift the bloom encoder
  uses; `Field`, a choice's rivals
  in a fixed array of `PATH_MAX_PER_PEER` slots; `best`, the least score
  among the scored rivals `choose` ranks; and `choose`, which
  keeps the pinned rivals while any rival is pinned, then the rivals of
  the highest tier present, then those that fit while any does, and
  takes the least score among the scored ones, unless a scored
  `Preferred` one scores at most the margin it is given times that
  least, when the least-scoring such one; then, of the scored ones
  within the margin of the least, only `Preferred` ones when a
  `Preferred` one was taken, the one on the fastest known medium, when
  that is faster than the medium of the one taken so far, also known;
  else the least latest round trip, one with none measured last; the
  lower index on every tie. The
  preferred precedence has no band: the link moves to a `Preferred` path
  and leaves it on the same ratio, so a preferred path whose score drifts
  across the margin of the best changes the active path once per
  crossing, each after a dwell, where two `Normal` paths keep the band
  from one over the margin to the margin. The least round trip
  is over the samples a path's window holds, at most the last 32 and
  none older than the round-trip window when the latest was taken, so it
  covers the shorter of the two: about 6.4 seconds on an active path
  probed every 200 ms, the whole window on a standby probed every second.
  A comparison therefore leans slightly toward leaving the active path;
  the score is local by the draft's note to Section 5.7. `steady` is the
  same score from the least round trip over the horizon, and `held`
  decides whether a change on score away from the active path waits for
  it, as above; a `Rival` carries both. `Hold`, the
  hold on the link's cost after a change of active path, holds the cost
  from before the change, counts receiver reports (`report`) and gives
  the cost while it is in force (`held`): before the switch dwell has
  passed since the change, or while fewer than `REPORTS` (2) reports
  have been counted. It reads no clock and allocates nothing: a hold's
  instants are the host's.
- `set.rs`: `PathSet`, the paths to one peer, keyed by the pair (local
  transport, peer address), with `PeerPath`, `Admission`, `PathRefused`,
  `Rebind`, `Roam`, `Medium` (BLE, wired, wireless or unknown; a BLE
  binding holds one path to a peer, every other medium up to
  `PATH_MAX_PER_TRANSPORT`), `PathState` and the limits
  `PATH_MAX_PER_PEER` and `PATH_MAX_PER_TRANSPORT`. It admits and evicts
  paths, binds the original path, moves a path's address on an authentic
  frame (`roam`) and rebinds deliberately (`rebind`), and holds a renewed
  link's one path (`holding`, of a path `reborn` under a new identifier
  with its slot and its count of failed frames). Only this module
  records a path's state (`transition`), moves its address
  (`readdress`), discards a path (`discard`, which leaves the set with
  no active path when it takes the active one) or makes one active
  (`activate`, which refuses a path never acked); the root crate's tests
  mark a path Dead through
  `mark_dead`, which exists only in test builds and under the
  `test-hooks` feature. `classify` is the
  source query: it answers with a `Match`, saying whether a pair is a
  proven path (Live, or acked once in this link, in any state), with
  whether it is the active one; a held path not yet proven; or no path.
- `wire.rs`: the path messages of multipath v1, `PathProbe` (0x52),
  `PathAck` (0x53) and `PathClose` (0x54), at the layouts of the draft's
  Sections 7.1 to 7.5, with `PathFlags`, `PathCaps`, `PathCloseReason`,
  the ack length rule (`ack_len`) and the parser for the extension block
  the first two may carry. Codec only: the root crate's node decodes each
  received path message and steps it into the link's `Bundle`, and sends
  the ones a `Bundle` emits.
  The module is public: its items are `proto::path::wire::...`.
- `tests/`: the unit tests; its README describes them.

## Invariants

- **Sans-IO.** Neither the set nor the machine reads a clock, performs
  I/O, logs or draws its own random numbers. Times come in as instants of
  the host's clock: the set takes the instant type, `I: time::Instant`,
  and `Bundle` the clock, `C: time::Clock`, whose instants every call
  takes. The set's path identifiers come from a draw the caller passes in;
  `Bundle` draws them, and each path's first `probe_id`, from the host's
  source `E: entropy::EntropySource`. What the machine needs to know of
  the host's transports comes through `Facts`, which needs no I/O. What a
  host would log is an output: `State`, `Capable`, `NotCapable` and
  `Refused`.
- **The driver slot is the host's.** Each path carries a slot, the type
  parameter `D`, for the state the host's transport driver keeps per
  path, such as a connected socket. The set makes it with `D::default()`
  when it admits the path, and no rule reads, changes or drops it. Every
  rule that discards a path returns it (`Admission::Added { evicted }`,
  `rebind`'s second value, `bind_original`'s `Ok`), and `roam` reports a
  path that is not active by index (`Roam::Standby`), so the host
  decides when a slot is released. `Bundle` does the same through its
  outputs: a path it discards comes back in `Output::Released`, the slot
  a moved path held in `Output::Moved`, and every path's slot from
  `close`.
- **The candidate table allocates nothing.** It is a fixed array, and a
  reported address is moved in, never copied. A test counts the calling
  thread's allocations around every operation on it.
- **A candidate never moves a path.** An address moves only on a path
  message (Section 5.3); the candidate arm never readdresses, and the test
  shell checks that every `Moved` comes from a probe or an ack.
- **A pair given up on is not probed again until it is released.**
  Every discard of an enabled bundle but a transport's removal holds back
  its pair, and a held-back entry is never admitted. A full table never
  replaces a held-back entry some source lists, so that source's repeats
  stay repeats.
- **`account` and `charge` allocate nothing.** `account` runs for every
  frame of the link and `charge` for every frame that fails to
  authenticate, so they touch only fixed fields; `account` clones the
  frame's address only for the roam, which shares its bytes. A test
  counts the calling thread's allocations around both.
- **Limits.** Dead paths count toward the per-transport and per-peer
  limits until one is evicted to make room. A BLE binding holds one path
  to a peer. The active path is never evicted.
- **The active path is proven.** A path is acked when it is bound, only
  an acked path becomes active (`rebind` and `activate` refuse any
  other), and nothing clears the ack, so `classify` answers
  `Proven { active: true, .. }` for the active pair.
- **An active path while an acked path is held.** Only a removed
  transport discards the active path, and the same step hands its place
  to another acked path, or reports the bundle orphaned when none is
  left. The test shell checks it after every step.
- **A `Backup` or `Never` path is active only while no path of a higher
  tier is Live, or while the pin names it.** Tiers come from the role
  the facts give at each step.
  A lower-tier active path yields at once, by a discretionary change that
  waits for neither samples nor the dwell, so a flapping `Normal` path
  takes the link back from a `Backup` one on each return; a mandatory
  change takes the highest tier Live; and a path held on a transport
  since set to `Never` carries the link only while no other path is
  Live, as Section 5.7 requires. The test shell checks after every step
  that no Live, acked path ranks above the active one unless the pin
  names the active one, and that every pinned change goes to a path the
  pin names.
- **The hold reads no clock: its instants are the host's
  `C::Instant`.** A hold records the instant of its change and is read
  against the instant `cost` is given; no wall-clock value exists in the
  module.
- **The cost held is the cost at the start of the step that changes
  path.** It is read before the step's first phase, so a report taken in
  the input phase can neither end the old hold first nor count toward
  the new one. The test shell checks after every step that changes path
  that `cost` at the step's instant is the same after it as before.
- **Within the highest tier Live, a path that carries a
  `FilterAnnounce` is chosen over one that does not.** Each path's link
  MTU is read from the facts at each step, lowered to the size the path
  is proven to carry where it has proven one, and compared with
  `FILTER_FRAME`, the frame the filter always travels in
  (`select::carried`, which the node reads for the peer's path MTU
  too). A path proven at no size above the smallest, as the original
  path is until a size is proven on it, is judged by its link MTU
  alone, and so is a path on a connection-oriented transport: the
  ladder steps down after any lost probe and no search raises the size
  there, so a smaller size proven on a stream may say only that a probe
  was lost. The preference
  comes after the pin and the tiers and before the preferred precedence
  and the score, and a change to a path for it alone waits for the
  dwell and the path's samples. With no Live path of that tier that
  carries the filter, the paths are chosen as without it.
- **A faster known medium wins within the margin, after the preferred
  precedence.** The facts give each path's medium at each step. Among
  the scored paths within `switch_margin` times the best, a cable is
  taken over a wireless network, and a wireless network over BLE; a
  medium the host does not know never takes or loses the link on this
  rule, so where every medium is unknown the choice is the score's
  alone. A change for it waits for the dwell and the path's samples,
  and an active path that scores more than the margin times the best
  gives way to the path ranked first, whatever its medium, as a
  `Preferred` one does. A path too small for a
  `FilterAnnounce` loses to one that carries it whatever its medium.
  Load on an active path of the faster medium, within the margin of the
  other at their best, does not move the link to the other before the
  load has lasted the horizon, even when the other is faster at its
  best, since the medium would take it back once the load followed it.
  The change for the medium is held under load too: while the path of
  the faster medium scores outside the margin of the active path's
  score over the horizon, load on the active path does not hand it the
  link before the load has lasted the horizon, so a loaded wireless
  network faster at its best does not trade the link with a slower
  cable as the load follows it.
- **The preferred precedence has no band.** A `Preferred` path is taken,
  after the dwell, while it scores at most `switch_margin` times the
  best, and given up, after the dwell, once it scores more, so its score
  crossing that ratio moves the link each time.
- **A discretionary or pinned change goes from a Live path to a Live
  path, and never on a tie between paths alike in role and in carrying
  a `FilterAnnounce`.** It runs only
  while the active path is Live, takes only a Live path, and, between
  paths that the pin does not set apart, of which neither alone carries
  a `FilterAnnounce`, whose roles neither differ in tier nor make
  one alone `Preferred`, and whose media are not both known and
  different, needs a strict margin, so such
  a path that scores the same as the active one never replaces it. The
  test shell checks every discretionary and pinned change it sees
  against the path active before it and the states after the call.
- **Path policy holds where a path is admitted, revived, moved or
  probed from Dead.** The link's class and kind are fixed when the bundle
  is built, and every check reads the facts at that moment, so a change
  in the facts governs the next check and is not itself an event; paths
  held from before are not checked again. The original path is never
  refused. The test shell checks every output that admits, revives or
  moves a path, and every probe of a Dead path, against the facts at
  that call.
- **Nothing but capability probes before the peer is capable.** Each is
  27 bytes on the original path, carrying its identifier; none goes while
  no candidate allows it, none closer to the last than the schedule
  allows, and `NotCapable` comes at most once and never after `Capable`.
  The test shell checks every call against its own reading of the
  candidates, the facts and the schedule.
- **Disabled is silent.** With multipath disabled the bundle emits no
  `Send` and no `Connect`, whatever it is given; the test shell checks it
  on every step of a disabled node.
- **The step order.** The link's cost read for a hold, recorded trips,
  the expiry of probes due before
  the step's instant, the peer turning capable, input, expiry, the
  choice of the active path, grace, sends, on every input, a poll
  included, so every input sees the same timers whether or not the host
  polled at each wake. A poll before `next_wake`, with the facts
  unchanged, does nothing, and after every step `next_wake` is `None` or
  later than the step's instant; the test shell checks both on every
  step.
- **States change only through the machine.** No file of the module
  defines a `set_` setter, and no test file but the set's own calls the
  set's methods that change a path's state, address or standing, so the
  machine's tests reach a state only through `Bundle`'s inputs. Two
  tests in `tests/mod.rs` check both, each against a planted line.
- **No wildcard arms.** Every match on an enum lists its variants; the
  module root denies `clippy::wildcard_enum_match_arm`, which reaches
  every file under it and their tests, and a test checks that it does. A
  variant added later is a compile error until every match names it.
- **The root crate's binding.** The root fixes `I` and `D` in aliases in
  `src/peer/mod.rs`, over its peer clock's instant and its UDP slot,
  `src/peer/udp_slot.rs`.
