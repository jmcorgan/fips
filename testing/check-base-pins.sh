#!/bin/bash
# ── Base image pin guard ────────────────────────────────────────────────────
# Every base image a CI image is built from, and every third-party image a CI
# suite runs, must be pinned by digest (name:tag@sha256:<index digest>). A tag
# such as debian:12 moves with every rebuild upstream, so two runs of one tree
# could build on different bases, and a result that stands for another run of
# the same tree (the builder's tree-identity skip) would stand on a base the
# skipped run never saw. testing/base-images.env holds the pins the suite
# scripts use and says how to move one.
#
# What counts as a violation, in the Dockerfiles, shell and Python scripts, env
# files and compose files under testing/ and packaging/, and in
# examples/sidecar-nostr-relay/Dockerfile.app, which the NAT lab builds its
# relay from:
#   * a FROM whose image has no @sha256: digest, unless it is a variable
#     (FROM ${BASE}, whose value is checked where it is set), a local fips-*
#     image, scratch, or a stage named earlier in the same file;
#   * an assignment in testing/base-images.env, or of a *_IMAGE variable in
#     packaging/build-floor.env, whose value has no digest;
#   * a compose `image:` naming a registry image without a digest (a
#     ${VAR:-default} or a local fips-* image is not one);
#   * on any line that is not a comment, a tag of one of the common
#     registry images in NAMES below (debian, ubuntu, alpine, nginx, ...)
#     with no digest after it. An image outside NAMES that a script names
#     only in a `docker run` is not seen; add its name when one is used;
# unless it is one of the individually justified references below.
#
# Not scanned, each with its reason: testing/boringtun/ and testing/interop/
# (run by hand, never by CI), testing/acl-allowlist/ (retired from CI), the
# rest of examples/ (example deployments for users, not CI images), and the
# workflows: the only images they name are the archlinux containers of the
# AUR publish jobs, which build no test image. This file is not scanned
# either: its fixtures name unpinned images on purpose.
#
# --current prints, for each pinned name:tag, the digest it is pinned to and
# the one the registry serves now, read with `docker buildx imagetools
# inspect`; it changes nothing. The guard runs its planted fixtures first, so
# a guard that has stopped seeing an unpinned base fails rather than passing.
#
# Exit 0 = every base pinned. Exit 1 = an unpinned reference. Exit 2 = the
# guard could not run, or its own fixtures did not behave; never a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MODE=check
case "${1:-}" in
    "") ;;
    --current) MODE=current ;;
    *) echo "check-base-pins: unknown option: $1" >&2; exit 2 ;;
esac

command -v python3 >/dev/null 2>&1 || {
    echo "check-base-pins: python3 not found; nothing was checked" >&2
    exit 2
}

python3 - "$ROOT" "$MODE" <<'PY'
import os
import re
import subprocess
import sys
import tempfile

root, mode = sys.argv[1], sys.argv[2]

SCAN_DIRS = ["testing", "packaging"]
EXTRA_FILES = ["examples/sidecar-nostr-relay/Dockerfile.app"]
EXCLUDED = ["testing/boringtun/", "testing/interop/", "testing/acl-allowlist/",
            "testing/check-base-pins.sh"]
# path::text, each a line the scan would flag that is no image anyone builds
# or runs, with the reason.
ALLOWED = {
    'testing/glibc-floor/test.sh::FIPS_BUILD_IMAGE="ubuntu:22.04"':
        "a fixture copy of build-floor.env for the floor check's own test; "
        "nothing is built from it",
    "testing/rpm-install/budget-test.sh::runtime image almalinux:9":
        "a step label in the stubbed dnf runs of the budget test; nothing is pulled",
}

PIN = "@sha256:"
NAMES = (r"(?:debian|ubuntu|alpine|python|fedora|almalinux|busybox|rust|archlinux"
         r"|nginx|golang|node|registry|redis|postgres|caddy|httpd|traefik)")
TOKEN = re.compile(r"(?<![\w./-])(" + NAMES + r":[A-Za-z0-9._-]+)(@sha256:[0-9a-f]{64})?")
# Upper case only, as every Dockerfile here writes it, so prose and Python
# ("from x import y") are not read as one.
FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+(?:AS|as)\s+(\S+))?")
IMAGE_KEY = re.compile(r"^\s*image:\s*['\"]?([^'\"\s#]+)")
ASSIGN = re.compile(r"^([A-Z][A-Z0-9_]*)=\"([^\"]*)\"")


def wanted(rel):
    """Whether a repository path is one the guard scans."""
    if any(rel.startswith(e) for e in EXCLUDED):
        return False
    if any(part.startswith(".") for part in rel.split("/")):
        return False
    base = os.path.basename(rel)
    return (base.startswith("Dockerfile")
            or base.endswith((".sh", ".py", ".env", ".yml", ".yaml")))


def files(top):
    """The files under top the guard scans, as paths relative to it."""
    out = []
    for d in SCAN_DIRS:
        for dirpath, dirnames, names in os.walk(os.path.join(top, d)):
            dirnames[:] = [n for n in dirnames if not n.startswith(".") and n != "target"]
            for n in names:
                rel = os.path.relpath(os.path.join(dirpath, n), top)
                if wanted(rel):
                    out.append(rel)
    out += [f for f in EXTRA_FILES if os.path.isfile(os.path.join(top, f))]
    return sorted(set(out))


def scan(top, allowed):
    """Every unpinned reference under top, and the allowed entries used."""
    problems, used = [], set()
    for rel in files(top):
        try:
            text = open(os.path.join(top, rel), encoding="utf-8", errors="replace").read()
        except OSError as e:
            problems.append(f"{rel}: cannot read: {e}")
            continue
        stages = set()
        base = os.path.basename(rel)
        for n, line in enumerate(text.splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            hit = None
            m = FROM.match(line)
            if m:
                img, alias = m.group(1), m.group(2)
                if alias:
                    stages.add(alias.lower())
                if not (img.startswith("$") or img == "scratch" or img.startswith("fips-")
                        or img.lower() in stages or PIN in img):
                    hit = f"FROM {img} has no digest"
            m = IMAGE_KEY.match(line)
            if not hit and m and base.endswith((".yml", ".yaml")):
                img = m.group(1)
                if not (img.startswith("$") or img.startswith("fips-") or PIN in img):
                    hit = f"image: {img} has no digest"
            m = ASSIGN.match(line)
            if not hit and m and base.endswith(".env"):
                var, val = m.group(1), m.group(2)
                if (base == "base-images.env" or var.endswith("_IMAGE")) and PIN not in val:
                    hit = f"{var}={val} has no digest"
            if not hit:
                for t in TOKEN.finditer(line):
                    if not t.group(2):
                        hit = f"{t.group(1)} has no digest"
                        break
            if not hit:
                continue
            key = next((a for a in allowed if a.split("::", 1)[0] == rel
                        and a.split("::", 1)[1] in line), None)
            if key:
                used.add(key)
                continue
            problems.append(f"{rel}:{n}: {hit}")
    return problems, used


def self_test():
    """Plant each kind of violation, and each allowed form, in a scratch tree."""
    cases = {
        "testing/a/Dockerfile": ("FROM debian:trixie-slim\n", 1),
        "testing/b/Dockerfile": ("FROM debian:trixie-slim@sha256:" + "a" * 64 + "\n", 0),
        "testing/c/Dockerfile": ("ARG BASE\nFROM ${BASE}\n", 0),
        "testing/d/Dockerfile": ("FROM rust:1.94@sha256:" + "b" * 64 + " AS build\nFROM build\n", 0),
        "testing/e/test.sh": ("cat <<'D'\nFROM ubuntu:24.04\nD\n", 1),
        "testing/f/test.sh": ('run_scenario x ubuntu:22.04\n# ubuntu:22.04 in a comment\n', 1),
        "testing/g/docker-compose.yml": ("services:\n  t:\n    image: example/tor:latest\n", 1),
        "testing/h/docker-compose.yml": ("services:\n  t:\n    image: ${X:-fips-local:1}\n", 0),
        "testing/base-images.env": ('DEBIAN12="debian:12"\n', 1),
        "packaging/build-floor.env": ('FIPS_BUILD_IMAGE="ubuntu:22.04@sha256:' + "c" * 64 + '"\n', 0),
        "testing/boringtun/Dockerfile": ("FROM debian:12\n", 0),
        "testing/i/sim.py": ('IMAGE = "alpine:3.20"\nfrom os import path\n', 1),
        "testing/j/test.sh": ("docker run --rm nginx:1.27 true\n", 1),
    }
    bad = []
    with tempfile.TemporaryDirectory() as tmp:
        for rel, (body, _) in cases.items():
            os.makedirs(os.path.dirname(os.path.join(tmp, rel)), exist_ok=True)
            open(os.path.join(tmp, rel), "w").write(body)
        problems, _ = scan(tmp, {})
        for rel, (_, want) in cases.items():
            got = sum(1 for p in problems if p.startswith(rel + ":"))
            if got != want:
                bad.append(f"{rel}: {got} finding(s), expected {want}")
    return bad


if mode == "current":
    pins = {}
    for rel in files(root):
        for line in open(os.path.join(root, rel), encoding="utf-8", errors="replace"):
            for m in re.finditer(r"(?<![\w./])([a-z0-9][a-z0-9./-]*:[A-Za-z0-9._-]+)@sha256:([0-9a-f]{64})",
                                 line):
                pins.setdefault(m.group(1), set()).add(m.group(2))
    for name in sorted(pins):
        r = subprocess.run(["docker", "buildx", "imagetools", "inspect", name,
                            "--format", "{{json .Manifest.Digest}}"],
                           capture_output=True, text=True, timeout=120)
        now = r.stdout.strip().strip('"').removeprefix("sha256:") if r.returncode == 0 else ""
        why = (r.stderr.strip().splitlines() or ["no output"])[-1]
        for d in sorted(pins[name]):
            if not now:
                state = f"unreadable: {why}"
            else:
                state = "current" if d == now else f"registry now {now}"
            print(f"{name}@sha256:{d}  {state}")
    sys.exit(0)

bad = self_test()
if bad:
    print("check-base-pins: the guard's own fixtures did not behave; nothing was checked:",
          file=sys.stderr)
    for b in bad:
        print(f"  {b}", file=sys.stderr)
    sys.exit(2)

problems, used = scan(root, ALLOWED)
stale = sorted(set(ALLOWED) - used)
if problems or stale:
    print("check-base-pins: base images without a digest:")
    for p in problems:
        print(f"  {p}")
    for s in stale:
        print(f"  allowed reference no longer present, remove it: {s}")
    print("  Pin each by digest (see testing/base-images.env for how), or, if it is "
          "no image\n  anything builds or runs, allow it in check-base-pins.sh with the reason.")
    sys.exit(1)
print(f"check-base-pins: every CI base image is pinned by digest ({len(files(root))} files scanned)")
sys.exit(0)
PY
