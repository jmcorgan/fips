"""Claim a free /24 for a scenario's network, atomically.

Two concurrent chaos runs used to request identical ranges: `ci-local.sh`
derived each child's subnet from its position in the suite list, so both runs
walked `10.30.0` through `10.30.12` and collided on every one of them. A run
index or a hashed offset only makes a collision unlikely, and a collision is
precisely the failure being removed, so this claims instead.

Claim-and-advance: attempt to create the network on a candidate range and, on
docker's own "Pool overlaps" error, move to the next. Docker's address pool is
then the arbiter and an overlap between two concurrent runs is *impossible*
rather than improbable. The pattern is taken from `testing/sidecar/scripts/
test-sidecar.sh:75-98`, which has been carrying it since 2026-07-19.

The claim has to happen before the topology is generated, not before the
compose file is written: node IPs derive from the subnet inside
`generate_topology`, and traffic shaping keys its filters on those addresses.
Claiming later yields a network on one range and `tc` filters on another, which
does not fail at bring-up and instead leaves the shaping matching nothing.
"""

from __future__ import annotations

import logging
import subprocess

log = logging.getLogger(__name__)

# Stay inside 10.30.0.0/16, which ci-local.sh already documents as clear of
# docker's default pool (172.17-31, 192.168) and of the fixed-subnet suites in
# 172.x. Sidecar has claimed 10.40.0.0/16; do not overlap it.
NET_BASE = "10.30"
NET_CANDIDATES = 200


class NetworkClaimError(RuntimeError):
    """No range could be claimed, or docker refused for another reason."""


def claim_network(
    name: str,
    labels: dict[str, str] | None = None,
    candidates: list[str] | None = None,
) -> str:
    """Create `name` on the first free /24 and return its CIDR.

    `candidates` pins the search to an explicit list, which is how `--subnet`
    opts out of claiming. A single pinned candidate that is already taken
    raises rather than advancing, so pinning fails loudly instead of silently
    overlapping a concurrent run.

    Raises NetworkClaimError if every candidate is taken, or immediately if
    docker fails for any reason other than an address-pool conflict. Retrying
    a real error 200 times would bury the reason for it.
    """
    ranges = candidates or [
        f"{NET_BASE}.{i}.0/24" for i in range(NET_CANDIDATES)
    ]
    label_args: list[str] = []
    for key, value in (labels or {}).items():
        label_args += ["--label", f"{key}={value}"]

    for subnet in ranges:
        proc = subprocess.run(
            ["docker", "network", "create", "--subnet", subnet]
            + label_args
            + [name],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            log.info("Claimed network %s on %s", name, subnet)
            return subnet
        err = (proc.stderr or "") + (proc.stdout or "")
        if "ool overlaps" in err:
            continue
        raise NetworkClaimError(
            f"docker network create {name} on {subnet} failed: {err.strip()}"
        )

    if candidates:
        raise NetworkClaimError(
            f"pinned subnet(s) {', '.join(candidates)} already in use; "
            f"another run holds the range"
        )
    raise NetworkClaimError(
        f"no free /24 in {NET_BASE}.0.0/16 after {NET_CANDIDATES} attempts"
    )


def remove_network(name: str) -> None:
    """Remove a claimed network, tolerating its absence.

    The network is `external:` to the generated compose file, so `compose down`
    leaves it behind and this is the only thing that reclaims the range.
    Failures are logged rather than raised: teardown runs on the failure path
    too, and losing a /24 is a leak, not a reason to mask the original error.
    """
    proc = subprocess.run(
        ["docker", "network", "rm", name],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        err = ((proc.stderr or "") + (proc.stdout or "")).strip()
        if "not found" in err or "No such network" in err:
            return
        log.warning("Could not remove network %s: %s", name, err)
