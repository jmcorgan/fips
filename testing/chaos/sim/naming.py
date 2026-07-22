"""Scoping suffix for names that live in a global namespace."""

from __future__ import annotations

import os


def name_suffix() -> str:
    """Return the suffix appended to globally-scoped names.

    Docker container names and the generated-config directory are shared
    across every simulation running on the host, so the harness exports
    ``FIPS_CI_NAME_SUFFIX`` to keep concurrent runs and concurrent
    scenarios apart. The suffix is empty when the variable is unset, so a
    bare ``chaos.sh`` run renders exactly the same names as it always has.
    """
    return os.environ.get("FIPS_CI_NAME_SUFFIX", "")
