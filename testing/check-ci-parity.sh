#!/bin/bash
# ── CI parity invariant guard ───────────────────────────────────────────────
# The GitHub integration matrix (.github/workflows/ci.yml) and the local
# default suite set (ci-local.sh) MUST run the same integration suites,
# EXCEPT for the deliberate local-only entries listed below. Adding a suite
# to one runner without the other means "local green" and "GitHub green" stop
# being equivalent claims.
#
# Deliberate local-only (NOT on the GitHub gate), with reason:
#   tor-socks5     — requires live Tor network; opt-in via --with-tor,
#                    unreliable on GitHub-hosted runners.
#   tor-directory  — same; live Tor dependency.
#
# Granularity-only differences folded before comparison (same coverage,
# different matrix shape — NOT a divergence):
#   deb-install    — GitHub splits into per-distro legs
#                    (deb-install-debian12/ubuntu24/ubuntu26); local runs all
#                    distros in one suite. Folded to "deb-install".
#   chaos-*        — GitHub fans each chaos scenario into its own matrix leg
#                    (type: chaos); local runs them all via the one CHAOS_SUITES
#                    path. The individual scenario names also differ cosmetically
#                    between runners (e.g. chaos-smoke-10 vs churn-mixed-10).
#                    Folded to a single "chaos" token on both sides.
#   dns-resolver   — single leg / single suite both sides; runs all scenarios.
#
# Exit 0 = parity clean. Exit 1 = unexpected divergence (suite names printed).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CI_LOCAL="$SCRIPT_DIR/ci-local.sh"
CI_YML="$PROJECT_ROOT/.github/workflows/ci.yml"

# Deliberate local-only allowlist (suites intentionally absent from GitHub).
ALLOWLIST="tor-socks5 tor-directory"

for f in "$CI_LOCAL" "$CI_YML"; do
    if [[ ! -f "$f" ]]; then
        echo "check-ci-parity: missing file: $f" >&2
        exit 2
    fi
done

# Extract and normalize both suite sets in Python (robust YAML parse of the
# matrix; regex extraction of the bash suite arrays). Folding rules above are
# applied identically to both sides so only genuine divergence surfaces.
python3 - "$CI_LOCAL" "$CI_YML" "$ALLOWLIST" <<'PY'
import re
import sys

ci_local_path, ci_yml_path, allowlist_raw = sys.argv[1], sys.argv[2], sys.argv[3]
allowlist = set(allowlist_raw.split())


def fold(name):
    """Collapse granularity-only matrix shape into canonical suite identity."""
    if name.startswith("chaos-") or name == "chaos":
        return "chaos"
    if name.startswith("deb-install"):
        return "deb-install"
    return name


# ── Local: parse the suite arrays from ci-local.sh ───────────────────────────
with open(ci_local_path, encoding="utf-8") as fh:
    local_src = fh.read()


def bash_array(var):
    m = re.search(rf"^{var}=\((.*?)\)", local_src, re.MULTILINE | re.DOTALL)
    if not m:
        return []
    body = m.group(1)
    # Quoted entries (chaos uses "display scenario flags"): first token is name.
    quoted = re.findall(r'"([^"]*)"', body)
    if quoted:
        return [entry.split()[0] for entry in quoted if entry.strip()]
    return [tok for tok in body.split() if tok.strip()]


local = set()
# Static, rekey, gateway, sidecar, acl, firewall, nostr, stun, dns, deb.
for var in ("STATIC_SUITES", "REKEY_SUITES", "ADMISSION_SUITES",
            "GATEWAY_SUITES", "SIDECAR_SUITES", "ACL_SUITES",
            "FIREWALL_SUITES", "NOSTR_RELAY_SUITES", "STUN_FAULTS_SUITES",
            "DNS_RESOLVER_SUITES", "DEB_INSTALL_SUITES"):
    local.update(bash_array(var))
# Chaos display names → fold to "chaos".
for _ in bash_array("CHAOS_SUITES"):
    local.add("chaos")
# NAT scenarios are stored bare (cone/symmetric/lan) and prefixed nat- at use.
for scen in bash_array("NAT_SUITES"):
    local.add(f"nat-{scen}")
# TOR_SUITES is the deliberate local-only set — excluded from the default path.

local = {fold(n) for n in local}

# ── GitHub: parse the integration matrix suite: values from ci.yml ───────────
import yaml  # noqa: E402

with open(ci_yml_path, encoding="utf-8") as fh:
    doc = yaml.safe_load(fh)

include = doc["jobs"]["integration"]["strategy"]["matrix"]["include"]
github = set()
for leg in include:
    if "suite" not in leg:
        continue
    # Chaos legs carry inconsistent suite: names (chaos-smoke-10 vs
    # churn-mixed-10) but a uniform type: chaos — fold via type, not name.
    if str(leg.get("type", "")) == "chaos":
        github.add("chaos")
    else:
        github.add(fold(str(leg["suite"])))

# ── Diff (subtract allowlist from local before comparison) ───────────────────
local_cmp = {n for n in local if n not in allowlist}

local_only = sorted(local_cmp - github)
github_only = sorted(github - local_cmp)

if local_only or github_only:
    print("CI parity FAILED: integration suite sets diverge.\n")
    if local_only:
        print("  Local-only (in ci-local.sh, missing from ci.yml, "
              "not in deliberate allowlist):")
        for n in local_only:
            print(f"    - {n}")
    if github_only:
        print("  GitHub-only (in ci.yml, missing from local default path):")
        for n in github_only:
            print(f"    - {n}")
    print("\n  Resolve by adding the suite to the other runner, or by adding "
          "it\n  to the deliberate local-only allowlist in "
          "check-ci-parity.sh with a\n  stated reason.")
    sys.exit(1)

print("CI parity OK: integration suite sets match "
      "(allowlist: " + ", ".join(sorted(allowlist)) + ").")
print(f"  {len(github)} canonical suites compared on each side.")
sys.exit(0)
PY
