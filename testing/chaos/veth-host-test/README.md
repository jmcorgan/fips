# veth-host-test

Support files for `../veth-host-test.sh`, the self-test of the chaos runner's
host `ip` command handling in `../sim/veth.py` and of the runner's NOT SCORED
verdict in `../sim/runner.py`. Nothing here runs on its own.

- `fake_docker.py` stands in for the `docker` CLI. The test puts a wrapper
  named `docker` first on `PATH` that runs it. It keeps a table of links and
  the namespace each is in, under a state directory named by
  `FAKE_DOCKER_STATE`. `docker exec` runs the runner's own shell script under
  bash, with `ip` and `cat /sys/class/net/...` replaced by functions acting on
  that table. A host helper (`docker run --rm ... --entrypoint ip`) runs in a
  detached process standing for the container, so killing the client leaves it
  running and only `docker rm -f NAME` stops it, as with docker. A plan file
  (`FAKE_DOCKER_PLAN`) makes chosen attempts at chosen host commands stall
  before their effect, stall after it, or start late. A rule's `after` list
  of `[LOG, REGEX]` pairs holds a late-start helper back from appearing, or a
  stall-before helper from running its command, until each regex matches in
  that log; `{self}` in a regex stands for the helper's own name. A gate
  still shut after `GATE_CAP_SECS` is logged as `gate-timeout NAME` and the
  helper goes on, so a runner that never reaches the awaited event fails its
  case rather than hanging it. Every call goes to `calls.log`, every change
  to the links to `effects.log`, and every helper's life to `helpers.log`. A
  late-start helper that has not appeared yet keeps its PID in
  `helpers/NAME.wait`, which docker cannot see and the test's cleanup kills.
- `drive.py` runs the code under test against the fake: one Ethernet pair
  through `VethManager.setup_all`, or the whole runner through its own entry
  point. `HOST_TIMEOUT` in its environment replaces `HOST_CMD_TIMEOUT_SECS`,
  so cases that time a command out more than once do not wait out the real
  bound each time.

Rules for changing these:

- The fake models only what veth setup and the runner's setup and teardown
  call. A new docker call in that path needs a matching answer here, or the
  `healthy` case and the call count in `../veth-host-test.sh` fail.
- The call count in the `healthy` case is the number of docker calls one pair
  makes when nothing stalls. A change to it is a change in what setup does on
  every run, and should be deliberate.
- A case's stall must be shaped like the defect it stands for: a helper that
  outlives its client, not a client that returns early.
- When a check depends on the order of two events the fake can see (a helper
  appearing, a removal, a move, another helper starting), the case sets that
  order with an `after` gate, never with a sleep. A loaded host slows the
  runner's chain of docker calls but not a helper's sleep, so a race set up
  by a sleep reds on a slow runner. The fake cannot see the runner's own
  client timeout fire, so a case that needs a helper to finish, or to be
  removed, inside the bound still depends on the host running an unstalled
  helper inside it; keep that margin wide.
