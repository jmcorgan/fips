# testing/root-tests

The container image the root-only unit tests run in under
`testing/ci-local.sh --tier`. The tests and their counts are in
[`../root-tests.sh`](../root-tests.sh); this directory holds only the image.

- `Dockerfile`: `debian:trixie-slim` plus `iproute2`, `nftables` and `procps`,
  the tools `root-tests.sh` checks for (`ip`, `nft`, `sysctl`). Nothing else:
  the `fips-mesh` library test binary is built on the host and mounted in
  read-only at its own path, with `root-tests.sh` at
  `/opt/fips/root-tests.sh` and this directory at `/opt/fips/root-tests`.
- `privileged.sh <bin> [--netns]`: the Ethernet and socket-buffer tests with
  `FIPS_TEST_PRIVILEGED=1`, as GitHub's `test-root` job runs them, passing
  only if at least one test passed. `--netns` leaves out the one test that
  reads `net.core.rmem_max`, which the kernel shows only in the host's own
  network namespace; the container never has it.
- `addrless-iface.sh <bin>`: makes the address-less dummy interface GitHub's
  Linux and musl jobs make (`fips-probe0`, `addrgenmode none`, failing if it
  has an address anyway) and runs the one test that reads it, with
  `FIPS_TEST_REQUIRE_FIXTURES=1`, against a glibc or a musl binary.

Both scripts are POSIX `sh`, since the image's `bash` is not something they
should need, and both print the test output, then exit 0 only on a pass.

`ci-local.sh` uses the image named by `FIPS_ROOT_TESTS_IMAGE`, by default
`fips-root-tests:trixie-1`, the tag the internal builder's image has carried
since it started running the root tests (2026-10-29). When the host does not
have it, the run builds it from this directory under that tag; the image
carries no CI labels, so the teardown keeps it for the next run. Bump the tag
with any change to the Dockerfile, so a host never runs a stale copy under the
new contents' name.

The container runs as uid 0 with `--network none`, `NET_ADMIN`, `SYS_ADMIN`,
`/dev/net/tun`, and AppArmor and the `/proc/sys` paths unconfined, the
permissions `root-tests.sh`'s header lists, for at most 20 minutes. The run
needs docker and no privilege of its own: there is no `sudo` in this path.
`ci-local.sh --root-tests` without a tier keeps running the script under
`sudo -n` instead, for a run by hand.
