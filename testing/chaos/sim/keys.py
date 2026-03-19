"""Key derivation wrapper, importing from shared testing library."""

import os
import sys

# Add testing/ to sys.path so we can import testing.lib.derive_keys
_TESTING_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
if _TESTING_DIR not in sys.path:
    sys.path.insert(0, _TESTING_DIR)

from lib.derive_keys import derive  # noqa: E402
