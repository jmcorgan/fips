#!/bin/bash
# ── CI parity invariant guard ───────────────────────────────────────────────
# The GitHub integration matrices (.github/workflows/ci.yml, swept across every
# job) and the local default suite set (ci-local.sh) MUST run the same
# integration suites, EXCEPT for the deliberate local-only entries listed below.
# Adding a suite to one runner without the other means "local green" and
# "GitHub green" stop being equivalent claims.
#
# Deliberate local-only (NOT on the GitHub gate), with reason:
#   tor-socks5     — requires live Tor network; opt-in via --with-tor,
#                    unreliable on GitHub-hosted runners.
#   tor-directory  — same; live Tor dependency.
#
# Deliberate GitHub-only (NOT in the local run), with reason:
#   deb-install ubuntu22 on arm64 — the local host is x86_64 and cannot run an
#                    arm64 package. The GitHub leg installs the arm64 package
#                    and starts the daemon on an arm runner.
#
# What is compared, and at what granularity:
#   chaos          — per scenario, plus its flags. GitHub fans each scenario
#                    into its own matrix leg carrying `scenario:` (and
#                    optionally `chaos_flags:`); local lists the same scenarios
#                    in CHAOS_SUITES as "display scenario flags". The `suite:`
#                    names differ cosmetically between runners and are ignored
#                    — `scenario:` is the identity.
#   deb-install    — per distro. GitHub splits into per-distro legs carrying
#                    `scenario:`, in a job of their own; local runs the same
#                    distro set in one suite, enumerated by ALL_SCENARIOS in
#                    deb-install/test.sh. A leg's `arch:` defaults to amd64,
#                    and only amd64 legs are compared with the local set, so
#                    an arm64 leg cannot stand in for a missing amd64 leg of
#                    the same distro. An arm64 leg must name a distro the
#                    local suite knows; any other arch is unidentifiable.
#   everything else — per suite name.
#
#   dns-resolver is the one leg still compared at leg granularity rather than
#   per scenario: it is a single leg and a single suite on both sides, and it
#   runs all of its scenarios internally. Its scenario list is NOT cross-checked.
#   On GitHub it is the one leg of a job of its own (it waits for the package
#   build), which the sweep across every job below finds like any other leg.
#
# The local suite set is discovered by sweeping ci-local.sh for *_SUITES arrays
# rather than from a hardcoded list of variable names, and every run_suite
# dispatch arm is then checked to have a backing array — a suite dispatched
# without one is invisible to a name-list sweep, which is how a real divergence
# went unnoticed.
#
# Exit 0 = parity clean. Exit 1 = unexpected divergence. Exit 2 = the guard
# could not run (missing file or missing dependency); never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CI_LOCAL="$SCRIPT_DIR/ci-local.sh"
CI_YML="$PROJECT_ROOT/.github/workflows/ci.yml"
DEB_TEST="$SCRIPT_DIR/deb-install/test.sh"
RPM_TEST="$SCRIPT_DIR/rpm-install/test.sh"

# Deliberate local-only allowlist (suites intentionally absent from GitHub).
ALLOWLIST="tor-socks5 tor-directory"

for f in "$CI_LOCAL" "$CI_YML" "$DEB_TEST" "$RPM_TEST"; do
    if [[ ! -f "$f" ]]; then
        echo "check-ci-parity: missing file: $f" >&2
        exit 2
    fi
done

if ! command -v python3 >/dev/null 2>&1; then
    echo "check-ci-parity: python3 not found; cannot verify CI parity" >&2
    exit 2
fi
if ! python3 -c "import yaml" >/dev/null 2>&1; then
    echo "check-ci-parity: python3 module 'yaml' not found; cannot verify CI parity" >&2
    echo "check-ci-parity: install it with 'pip3 install pyyaml'" >&2
    exit 2
fi

python3 - "$CI_LOCAL" "$CI_YML" "$DEB_TEST" "$RPM_TEST" "$ALLOWLIST" <<'PY'
import re
import sys

import yaml

ci_local_path, ci_yml_path, deb_test_path, rpm_test_path, allowlist_raw = sys.argv[1:6]
allowlist = set(allowlist_raw.split())

with open(ci_local_path, encoding="utf-8") as fh:
    local_src = fh.read()
with open(deb_test_path, encoding="utf-8") as fh:
    deb_src = fh.read()
with open(rpm_test_path, encoding="utf-8") as fh:
    rpm_src = fh.read()


def bash_array_entries(var):
    """Full entries of a bash array, in order, quotes stripped."""
    m = re.search(rf"^{var}=\((.*?)\)", local_src, re.MULTILINE | re.DOTALL)
    if not m:
        return []
    body = m.group(1)
    quoted = re.findall(r'"([^"]*)"', body)
    if quoted:
        return [e.strip() for e in quoted if e.strip()]
    return [tok for tok in body.split() if tok.strip()]


def discovered_arrays():
    """Every *_SUITES array in ci-local.sh, by name.

    Swept rather than hardcoded: a suite whose array is not on a fixed list
    would otherwise be invisible to this guard.
    """
    return {
        name + "_SUITES": bash_array_entries(name + "_SUITES")
        for name in re.findall(r"^([A-Z_]+)_SUITES=\(", local_src, re.MULTILINE)
    }


arrays = discovered_arrays()

# ── Local side ───────────────────────────────────────────────────────────────
# Chaos: "display scenario flags" — compare the scenario and its flags.
local_chaos = {}
for entry in arrays.get("CHAOS_SUITES", []):
    parts = entry.split()
    if len(parts) < 2:
        continue
    local_chaos[parts[1]] = " ".join(parts[2:])

# deb-install: one local suite that runs the distro set enumerated in its script.
m = re.search(r'^ALL_SCENARIOS="([^"]*)"', deb_src, re.MULTILINE)
local_deb = set(m.group(1).split()) if m else set()
# rpm-install: likewise, per scenario, enumerated by ALL_SCENARIOS in its script.
m = re.search(r'^ALL_SCENARIOS="([^"]*)"', rpm_src, re.MULTILINE)
local_rpm = set(m.group(1).split()) if m else set()

# Everything else: suite names, with NAT stored bare and prefixed at use.
local = set()
for name, entries in arrays.items():
    if name in ("CHAOS_SUITES", "DEB_INSTALL_SUITES", "RPM_INSTALL_SUITES"):
        continue
    names = [e.split()[0] for e in entries]
    if name == "NAT_SUITES":
        local |= {f"nat-{n}" for n in names}
    else:
        local |= set(names)

# ── GitHub side ──────────────────────────────────────────────────────────────
with open(ci_yml_path, encoding="utf-8") as fh:
    doc = yaml.safe_load(fh)

# Sweep every job's matrix rather than one named job: the install legs live in
# a job of their own so the rest of the integration matrix does not wait on the
# package build, and a guard keyed to a job name reports them as local-only the
# moment they move. Identity comes from the leg's own fields, so where a leg
# lives does not matter; a leg deleted from every job still shows up as
# local-only, because the local side is the reference.
include = []
for job in (doc.get("jobs") or {}).values():
    legs = (((job.get("strategy") or {}).get("matrix") or {}).get("include") or [])
    if isinstance(legs, list):
        include += [leg for leg in legs if isinstance(leg, dict)]
if not include:
    print("check-ci-parity: no matrix include: found in any job of "
          f"{ci_yml_path}; cannot verify CI parity", file=sys.stderr)
    sys.exit(2)
github_chaos, github_deb, github_rpm, github = {}, set(), set(), set()
# Deliberate GitHub-only install legs on another architecture, by distro. Kept
# out of github_deb: were they in it, deleting the amd64 leg of a distro that
# also has an arm64 leg would leave the distro in the set and pass.
github_deb_extra = {}
malformed = []
for leg in include:
    if "suite" not in leg and "scenario" not in leg:
        continue
    kind = str(leg.get("type", ""))
    if kind == "rpm-install":
        if "scenario" not in leg:
            malformed.append(f"{leg.get('suite', '(unnamed leg)')} has type "
                             "rpm-install but no scenario:")
            continue
        github_rpm.add(str(leg["scenario"]))
        continue
    if kind in ("chaos", "deb-install"):
        # scenario: is the identity for these; suite: is cosmetic.
        if "scenario" not in leg:
            malformed.append(f"{leg.get('suite', '(unnamed leg)')} has type "
                             f"{kind} but no scenario:")
            continue
        if kind == "chaos":
            github_chaos[str(leg["scenario"])] = str(leg.get("chaos_flags", ""))
            continue
        arch = str(leg.get("arch", "amd64"))
        if arch == "amd64":
            github_deb.add(str(leg["scenario"]))
        elif arch == "arm64":
            github_deb_extra.setdefault(arch, set()).add(str(leg["scenario"]))
        else:
            malformed.append(f"deb-install leg {leg['scenario']} has arch "
                             f"{arch}, which is neither amd64 nor arm64")
    elif "suite" in leg:
        github.add(str(leg["suite"]))
    else:
        malformed.append(f"leg with scenario {leg['scenario']} has no suite: "
                         f"and no chaos/deb-install type")

# ── Dispatch cross-check: every run_suite arm needs a backing array ──────────
# A suite dispatched without an array is invisible to the sweep above, so the
# guard would report it as GitHub-only forever without ever naming the cause.
body = re.search(r"^run_suite\(\).*?^\}", local_src, re.MULTILINE | re.DOTALL)
dispatch_uncovered = []
if body is None:
    print("check-ci-parity: could not locate run_suite() in ci-local.sh", file=sys.stderr)
    sys.exit(2)

# Arms sit at one fixed indentation inside the case block. Pin to it, taken from
# the first arm rather than assumed, so a body line that happens to end in ')'
# cannot be read as an arm.
arm_re = re.compile(r"^([ \t]+)['\"]?([a-z0-9|*_.-]+)['\"]?\)", re.MULTILINE)
first = arm_re.search(body.group(0))
if first is None:
    print("check-ci-parity: no dispatch arms found in run_suite()", file=sys.stderr)
    sys.exit(2)

indent = first.group(1)
# An arm-shaped line at a different indent is not skipped silently: it would
# make this check quietly stop covering a suite, which is the failure mode the
# check exists to prevent.
odd_arms = [
    m.group(2) for m in arm_re.finditer(body.group(0)) if m.group(1) != indent
]
if odd_arms:
    print("check-ci-parity: run_suite has arm-shaped lines at an unexpected "
          f"indent, so the dispatch check cannot be trusted: {', '.join(odd_arms)}",
          file=sys.stderr)
    sys.exit(2)
known = (set(local) | set(local_chaos) | local_deb | local_rpm
         | {e.split()[0] for e in arrays.get("DEB_INSTALL_SUITES", [])}
         | {e.split()[0] for e in arrays.get("RPM_INSTALL_SUITES", [])})
for m in arm_re.finditer(body.group(0)):
    if m.group(1) != indent:
        continue
    for arm in m.group(2).split("|"):
        if arm == "*":
            continue              # the unknown-suite error arm, not a suite
        if arm == "chaos-*":
            # Dispatches any chaos-<name> through a fallback, so its vocabulary
            # is unbounded; the chaos scenario comparison covers it instead.
            continue
        if arm not in known:
            dispatch_uncovered.append(arm)

# ── Diff ─────────────────────────────────────────────────────────────────────
local_cmp = {n for n in local if n not in allowlist}

local_only = sorted(local_cmp - github)
github_only = sorted(github - local_cmp)
chaos_local_only = sorted(set(local_chaos) - set(github_chaos))
chaos_github_only = sorted(set(github_chaos) - set(local_chaos))
chaos_flag_drift = sorted(
    (s, local_chaos[s], github_chaos[s])
    for s in set(local_chaos) & set(github_chaos)
    if local_chaos[s] != github_chaos[s]
)
deb_local_only = sorted(local_deb - github_deb)
deb_github_only = sorted(github_deb - local_deb)
# An extra-arch leg for a distro the local suite does not know is still drift.
deb_github_only += sorted(
    f"{d} ({arch})"
    for arch, distros in github_deb_extra.items()
    for d in distros - local_deb
)

rpm_local_only = sorted(local_rpm - github_rpm)
rpm_github_only = sorted(github_rpm - local_rpm)

problems = (local_only or github_only or chaos_local_only or chaos_github_only
            or chaos_flag_drift or deb_local_only or deb_github_only
            or rpm_local_only or rpm_github_only
            or dispatch_uncovered or malformed)

if problems:
    print("CI parity FAILED: the two runners do not cover the same work.\n")
    if local_only:
        print("  Suites local-only (in ci-local.sh, missing from ci.yml, "
              "not in the deliberate allowlist):")
        for n in local_only:
            print(f"    - {n}")
    if github_only:
        print("  Suites GitHub-only (in ci.yml, missing from the local default path):")
        for n in github_only:
            print(f"    - {n}")
    if chaos_local_only:
        print("  Chaos scenarios local-only:")
        for n in chaos_local_only:
            print(f"    - {n}")
    if chaos_github_only:
        print("  Chaos scenarios GitHub-only:")
        for n in chaos_github_only:
            print(f"    - {n}")
    if chaos_flag_drift:
        print("  Chaos scenarios whose flags differ between runners:")
        for name, lflags, gflags in chaos_flag_drift:
            print(f"    - {name}: local '{lflags}' vs GitHub '{gflags}'")
    if deb_local_only:
        print("  deb-install distros local-only:")
        for n in deb_local_only:
            print(f"    - {n}")
    if deb_github_only:
        print("  deb-install distros GitHub-only:")
        for n in deb_github_only:
            print(f"    - {n}")
    if rpm_local_only:
        print("  rpm-install scenarios local-only:")
        for n in rpm_local_only:
            print(f"    - {n}")
    if rpm_github_only:
        print("  rpm-install scenarios GitHub-only:")
        for n in rpm_github_only:
            print(f"    - {n}")
    if malformed:
        print("  Matrix legs this guard cannot identify:")
        for n in malformed:
            print(f"    - {n}")
    if dispatch_uncovered:
        print("  run_suite dispatches these with no backing *_SUITES array, so "
              "this guard\n  cannot see them in the local set:")
        for n in dispatch_uncovered:
            print(f"    - {n}")
    print("\n  Resolve by adding the suite to the other runner, by giving a "
          "dispatchable\n  suite a *_SUITES array, or by adding it to the "
          "deliberate local-only\n  allowlist in check-ci-parity.sh with a "
          "stated reason.")
    sys.exit(1)

total = len(github) + len(github_chaos) + len(github_deb) + len(github_rpm)
print("CI parity OK: both runners cover the same work "
      "(allowlist: " + ", ".join(sorted(allowlist)) + ").")
print(f"  {len(github)} suites, {len(github_chaos)} chaos scenarios "
      f"(flags compared), {len(github_deb)} deb-install distros, "
      f"{len(github_rpm)} rpm-install scenarios "
      f"— {total} legs on each side.")
for arch, distros in sorted(github_deb_extra.items()):
    legs = "leg" if len(distros) == 1 else "legs"
    print(f"  plus {len(distros)} GitHub-only {arch} install {legs} "
          f"({', '.join(sorted(distros))}).")
sys.exit(0)
PY
