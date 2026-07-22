"""Scoping suffix for names that live in a global namespace."""

from __future__ import annotations

import hashlib
import os
import sys


def name_suffix() -> str:
    """Return the suffix appended to globally-scoped names.

    Docker container names and the generated-config directory are shared
    across every simulation running on the host, so the harness exports
    ``FIPS_CI_NAME_SUFFIX`` to keep concurrent runs and concurrent
    scenarios apart. The suffix is empty when the variable is unset, so a
    bare ``chaos.sh`` run renders exactly the same names as it always has.
    """
    return os.environ.get("FIPS_CI_NAME_SUFFIX", "")


def veth_token(suffix: str) -> str:
    """Shorten a name suffix to four hex characters.

    Host interface names have only 15 characters to work with, far fewer
    than the suffix needs, so concurrent scenarios are told apart by a
    hash of it instead. Empty for an empty suffix, so a bare run's
    interface names are unchanged.
    """
    if not suffix:
        return ""
    return hashlib.sha1(suffix.encode()).hexdigest()[:4]


if __name__ == "__main__":
    # Print the token for each suffix given on the command line, one per
    # line. ci-cleanup.sh reaps host interfaces by token and calls this
    # rather than re-deriving the hash, so widening the token here cannot
    # leave the reaper matching the old width.
    for arg in sys.argv[1:]:
        print(veth_token(arg))
