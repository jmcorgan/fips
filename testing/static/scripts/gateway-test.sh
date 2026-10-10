#!/bin/bash
# Gateway integration test: non-FIPS LAN client reaches mesh HTTP server.
#
# Topology:
#   gw-client (non-FIPS) → gw-gateway (fips + fips-gateway) → gw-server (fips + http)
#
# Usage:
#   ./scripts/gateway-test.sh [inject-config | selftest]
#
# Subcommands:
#   inject-config  — post-process generated configs to add the gateway section
#   selftest       — check the output readers against canned input
#   (no args)      — run the test (containers must be running)
set -e

trap 'echo ""; echo "Test interrupted"; exit 130' INT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../lib/wait-converge.sh"

GENERATED_DIR="$SCRIPT_DIR/../generated-configs${FIPS_CI_NAME_SUFFIX:-}"
ENV_FILE="$GENERATED_DIR/npubs.env"

GATEWAY="fips-gw-gateway${FIPS_CI_NAME_SUFFIX:-}"
SERVER="fips-gw-server${FIPS_CI_NAME_SUFFIX:-}"
SERVER2="fips-gw-server-2${FIPS_CI_NAME_SUFFIX:-}"
CLIENT="fips-gw-client${FIPS_CI_NAME_SUFFIX:-}"
CLIENT2="fips-gw-client-2${FIPS_CI_NAME_SUFFIX:-}"

# LAN-side IPv6 addressing. run_gateway claims a per-run /64 and exports
# FIPS_GW_LAN6_PREFIX; unset (standalone / GitHub) these render the base
# compose's fd02:: addresses, byte-identical to before. GW_DNS is the gateway's
# LAN address (nameserver + route next-hop); GW_CLIENT_LAN is gw-client's LAN
# address (inbound port-forward target). fd01::/112 (the virtual pool) is NOT
# claimed and stays literal below.
GW_LAN6_PREFIX="${FIPS_GW_LAN6_PREFIX:-fd02}"
GW_DNS="${GW_LAN6_PREFIX}::10"
GW_CLIENT_LAN="${GW_LAN6_PREFIX}::20"

# ── inject-config subcommand ─────────────────────────────────────────────

inject_gateway_config() {
    local config_file="$GENERATED_DIR/gateway/node-a.yaml"

    if [ ! -f "$config_file" ]; then
        echo "Error: $config_file not found. Run generate-configs.sh gateway first." >&2
        return 1
    fi

    echo "Injecting gateway config into $config_file"
    # Opening with 'w' truncates in place and keeps the inode, which the
    # container's single-file bind mount of this file needs.
    python3 - "$config_file" "$GW_CLIENT_LAN" <<'PYEOF' || return 1
import sys, yaml
path, client = sys.argv[1:3]

with open(path) as f:
    cfg = yaml.safe_load(f)

cfg['gateway'] = {
    'enabled': True,
    'pool': 'fd01::/112',
    # A placeholder. Docker does not promise which interface the LAN
    # network gets, so the gateway container's entrypoint replaces this with
    # the interface holding the gateway's LAN address before fips-gateway
    # starts. The LAN-side masquerade and the proxy NDP entries use it.
    'lan_interface': 'eth1',
    'dns': {
        'listen': '[::]:53',
        'ttl': 5,
    },
    'pool_grace_period': 5,
    'port_forwards': [
        {
            'listen_port': 18080,
            'proto': 'tcp',
            'target': f'[{client}]:8080',
        },
        # 6B: second TCP forward — exercises multiple simultaneous TCP
        # rules sharing the same LAN backend on a different listen port.
        {
            'listen_port': 18082,
            'proto': 'tcp',
            'target': f'[{client}]:8081',
        },
        # 6A: UDP forward — exercises the runtime UDP DNAT path (rule
        # shape + conntrack handling) end-to-end.
        {
            'listen_port': 18081,
            'proto': 'udp',
            'target': f'[{client}]:8081',
        },
    ],
}

with open(path, 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
PYEOF
    echo "  ✓ Gateway config injected"
    return 0
}

# ── Readers ──────────────────────────────────────────────────────────────
#
# Each reader parses one tool's output on stdin and prints a single answer.
# A reader that cannot answer exits non-zero and prints nothing, rather than
# printing a default a check could mistake for an answer. Addresses are
# compared as addresses, never as strings: ip prints fd02:0:0:0::10 as
# fd02::10. Arguments reach Python through sys.argv.

# The interface holding address $1, from `ip -6 -o addr show`. Fails when no
# interface holds it or more than one does.
lan_iface() {
    python3 -c '
import ipaddress, sys
want = ipaddress.ip_address(sys.argv[1])
holders = set()
for line in sys.stdin:
    f = line.split()
    if len(f) < 4 or f[2] != "inet6":
        continue
    try:
        addr = ipaddress.ip_interface(f[3]).ip
    except ValueError:
        continue
    if addr == want:
        holders.add(f[1].split("@")[0])
if len(holders) != 1:
    sys.exit(1)
print(holders.pop())
' "$@"
}

# The gateway's lan_interface, from a show_gateway response.
gw_iface() {
    python3 -c '
import json, sys
try:
    r = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
if not isinstance(r, dict) or r.get("status") != "ok":
    sys.exit(1)
data = r.get("data")
if not isinstance(data, dict):
    sys.exit(1)
name = data.get("lan_interface")
if not isinstance(name, str) or not name:
    sys.exit(1)
print(name)
'
}

# The output interface of the LAN masquerade (the one rule matching
# iifname "fips0" and masquerading), from `nft list table inet fips_gateway`.
masq_iface() {
    python3 -c '
import re, sys
found = []
for line in sys.stdin:
    if "iifname \"fips0\"" not in line or not re.search(r"\bmasquerade\b", line):
        continue
    m = re.search(r"\boifname \"([^\"]+)\"", line)
    found.append(m.group(1) if m else "")
if len(found) != 1 or not found[0]:
    sys.exit(1)
print(found[0])
'
}

# How many per-mapping SNAT rules come before the LAN masquerade, from
# `nft list table inet fips_gateway`. NAT statements are terminal, so a SNAT
# listed first takes an inbound forwarded flow from that mapping's peer and
# the masquerade never runs; the right answer is 0. Fails when the listing
# does not hold exactly one LAN masquerade.
snat_before_masq() {
    python3 -c '
import re, sys
snat = 0
before = None
masq = 0
for line in sys.stdin:
    if "iifname \"fips0\"" in line and re.search(r"\bmasquerade\b", line):
        masq += 1
        before = snat
    elif re.search(r"\bsaddr [0-9a-f:]+ .*\bsnat\b", line):
        snat += 1
if masq != 1:
    sys.exit(1)
print(before)
'
}

# The SNAT target of the one rule whose source match is mesh address $1, from
# `nft list table inet fips_gateway`. Fails when no rule or more than one
# matches.
snat_to() {
    python3 -c '
import ipaddress, re, sys
want = ipaddress.ip_address(sys.argv[1])
found = []
for line in sys.stdin:
    m = re.search(r"\bsaddr ([0-9a-f:]+) .*\bsnat\b.*?\bto \[?([0-9a-f:]+)", line)
    if not m:
        continue
    try:
        if ipaddress.ip_address(m.group(1)) == want:
            found.append(ipaddress.ip_address(m.group(2)))
    except ValueError:
        sys.exit(1)
if len(found) != 1:
    sys.exit(1)
print(found[0])
' "$@"
}

# The device of the proxy neighbour entry for address $1, from
# `ip -6 neigh show proxy`, whose lines read `ADDR dev DEV proxy`. Fails when
# no entry matches or matching entries name different devices.
proxy_dev() {
    python3 -c '
import ipaddress, sys
want = ipaddress.ip_address(sys.argv[1])
devs = set()
for line in sys.stdin:
    f = line.split()
    if len(f) < 3 or "dev" not in f[1:-1]:
        continue
    try:
        addr = ipaddress.ip_address(f[0])
    except ValueError:
        continue
    if addr == want:
        devs.add(f[f.index("dev", 1) + 1])
if len(devs) != 1:
    sys.exit(1)
print(devs.pop())
' "$@"
}

# How many mappings have mesh_addr $1, from a show_mappings response. Fails
# on an error response or one without a mappings list, so a failed query
# cannot read as zero mappings.
server_mapped() {
    python3 -c '
import ipaddress, json, sys
want = ipaddress.ip_address(sys.argv[1])
try:
    r = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
if not isinstance(r, dict) or r.get("status") != "ok":
    sys.exit(1)
data = r.get("data")
if not isinstance(data, dict) or not isinstance(data.get("mappings"), list):
    sys.exit(1)
hits = 0
for m in data["mappings"]:
    try:
        if ipaddress.ip_address(m["mesh_addr"]) == want:
            hits += 1
    except (KeyError, TypeError, ValueError):
        sys.exit(1)
print(hits)
' "$@"
}

# The reply destination of the conntrack entries for PROTO $1 to port $2, from
# `conntrack -L -f ipv6`. Of each line's two tuples the first is the original
# direction and the second the reply, so the reply destination is the second
# dst=. It shows which rule rewrote the flow's source: the gateway's LAN
# address for the LAN masquerade, a pool address for a mapping's SNAT, or the
# sender's own address for no rewrite. Fails when no entry matches or the
# matching entries disagree.
reply_dst() {
    python3 -c '
import ipaddress, sys
proto, dport = sys.argv[1], sys.argv[2]
found = set()
for line in sys.stdin:
    f = line.split()
    if not f or f[0] != proto:
        continue
    dports = [t[6:] for t in f if t.startswith("dport=")]
    dsts = [t[4:] for t in f if t.startswith("dst=")]
    if not dports or dports[0] != dport:
        continue
    try:
        found.add(ipaddress.ip_address(dsts[1]))
    except (IndexError, ValueError):
        sys.exit(1)
if len(found) != 1:
    sys.exit(1)
print(found.pop())
' "$@"
}

# The set of input interfaces on the DNAT rules whose destination lies in pool
# $1, comma-joined and sorted, from `nft list table inet fips_gateway`. Port
# forward DNATs, whose destination is the gateway's own address, are not
# counted. Fails when no such rule exists or one has no iifname match.
dnat_iifs() {
    python3 -c '
import ipaddress, re, sys
pool = ipaddress.ip_network(sys.argv[1])
found = set()
lines = 0
for line in sys.stdin:
    if not re.search(r"\bdnat\b", line):
        continue
    m = re.search(r"\bip6 daddr ([0-9a-f:]+)\b", line)
    if not m:
        continue
    try:
        if ipaddress.ip_address(m.group(1)) not in pool:
            continue
    except ValueError:
        sys.exit(1)
    lines += 1
    i = re.search(r"\biifname \"([^\"]+)\"", line)
    if not i:
        sys.exit(1)
    found.add(i.group(1))
if not lines:
    sys.exit(1)
print(",".join(sorted(found)))
' "$@"
}

# The mesh address the DNAT rule for virtual IP $1 translates to, from
# `nft list table inet fips_gateway`. Fails when no rule or more than one
# matches.
dnat_to() {
    python3 -c '
import ipaddress, re, sys
want = ipaddress.ip_address(sys.argv[1])
found = []
for line in sys.stdin:
    m = re.search(r"\bdaddr ([0-9a-f:]+) .*\bdnat\b.*?\bto \[?([0-9a-f:]+)", line)
    if not m:
        continue
    try:
        if ipaddress.ip_address(m.group(1)) == want:
            found.append(ipaddress.ip_address(m.group(2)))
    except ValueError:
        sys.exit(1)
if len(found) != 1:
    sys.exit(1)
print(found[0])
' "$@"
}

# Prints "ok" when the table holds the two rules that keep other interfaces
# off the mesh, from `nft -j list table inet fips_gateway`, given the LAN
# interface $1 and the pool $2: in chain forward, a drop of traffic into
# fips0 from any interface but the LAN unless it is established or related;
# in chain raw_prerouting, a drop of traffic to the pool from any interface
# but the LAN and lo. Fails otherwise. The ct state match is accepted in the
# form nft 1.0.9 prints for the rule (negation of the established,related
# set) and as an explicit mask compared with zero.
lan_drops_json() {
    python3 -c '
import ipaddress, json, sys
lan, pool = sys.argv[1], ipaddress.ip_network(sys.argv[2])
try:
    doc = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
rules = [e["rule"] for e in doc.get("nftables", []) if isinstance(e, dict) and "rule" in e]

def matches(rule):
    return [x["match"] for x in rule.get("expr", []) if isinstance(x, dict) and "match" in x]

def drops(rule):
    return any(isinstance(x, dict) and "drop" in x for x in rule.get("expr", []))

def meta(m, key, op, value):
    return m.get("left") == {"meta": {"key": key}} and m.get("op") == op and m.get("right") == value

def flags(v):
    if isinstance(v, str):
        return {v}
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return set(v)
    if isinstance(v, dict) and isinstance(v.get("set"), list):
        return set(v["set"])
    return None

def not_est_rel(m):
    ct = {"ct": {"key": "state"}}
    want = {"established", "related"}
    if m.get("op") == "!" and m.get("left") == ct:
        return flags(m.get("right")) == want
    left = m.get("left")
    if m.get("op") == "==" and m.get("right") == 0 and isinstance(left, dict) and isinstance(left.get("&"), list):
        a = left["&"]
        return len(a) == 2 and a[0] == ct and flags(a[1]) == want
    return False

def forward_drop(rule):
    ms = matches(rule)
    return (rule.get("chain") == "forward" and drops(rule)
        and any(meta(m, "oifname", "==", "fips0") for m in ms)
        and any(meta(m, "iifname", "!=", lan) for m in ms)
        and any(not_est_rel(m) for m in ms))

def pool_drop(rule):
    ms = matches(rule)
    def prefix(m):
        r = m.get("right")
        if m.get("op") != "==" or m.get("left") != {"payload": {"protocol": "ip6", "field": "daddr"}}:
            return False
        if not isinstance(r, dict) or "prefix" not in r:
            return False
        try:
            net = ipaddress.ip_network("%s/%s" % (r["prefix"]["addr"], r["prefix"]["len"]))
        except (KeyError, ValueError):
            return False
        return net == pool
    return (rule.get("chain") == "raw_prerouting" and drops(rule)
        and any(meta(m, "iifname", "!=", lan) for m in ms)
        and any(meta(m, "iifname", "!=", "lo") for m in ms)
        and any(prefix(m) for m in ms))

if any(forward_drop(r) for r in rules) and any(pool_drop(r) for r in rules):
    print("ok")
else:
    sys.exit(1)
' "$@"
}

# Prints "ok" when chain raw_prerouting holds the drop of packets from a
# mapped mesh address, from `nft -j list table inet fips_gateway`: a lookup of
# the source in set fips_mesh_sources, for packets arriving on neither fips0
# nor lo. Fails otherwise.
forged_drop_json() {
    python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
def ok(rule):
    if rule.get("chain") != "raw_prerouting":
        return False
    exprs = rule.get("expr", [])
    ms = [x["match"] for x in exprs if isinstance(x, dict) and "match" in x]
    def has(left, op, right):
        return any(m.get("left") == left and m.get("op") == op and m.get("right") == right for m in ms)
    return (has({"meta": {"key": "iifname"}}, "!=", "fips0")
        and has({"meta": {"key": "iifname"}}, "!=", "lo")
        and has({"payload": {"protocol": "ip6", "field": "saddr"}}, "==", "@fips_mesh_sources")
        and any(isinstance(x, dict) and "drop" in x for x in exprs))
rules = [e["rule"] for e in doc.get("nftables", []) if isinstance(e, dict) and "rule" in e]
if any(ok(r) for r in rules):
    print("ok")
else:
    sys.exit(1)
'
}

# Succeeds when the set listing from `nft -j list set inet fips_gateway
# fips_mesh_sources` holds address $1.
set_holds() {
    python3 -c '
import ipaddress, json, sys
want = ipaddress.ip_address(sys.argv[1])
try:
    doc = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
for e in doc.get("nftables", []):
    if isinstance(e, dict) and isinstance(e.get("set"), dict):
        for x in e["set"].get("elem", []):
            try:
                if isinstance(x, str) and ipaddress.ip_address(x) == want:
                    sys.exit(0)
            except ValueError:
                pass
sys.exit(1)
' "$@"
}

# The reply-tuple destination port of the conntrack entry for UDP to address
# $1 port $2, and whether it has seen a reply ("unreplied" or "replied"),
# from `conntrack -L -f ipv6`. Fails unless exactly one entry matches.
udp_entry() {
    python3 -c '
import ipaddress, sys
dst, dport = ipaddress.ip_address(sys.argv[1]), sys.argv[2]
found = []
for line in sys.stdin:
    f = line.split()
    if not f or f[0] != "udp":
        continue
    dsts = [t[4:] for t in f if t.startswith("dst=")]
    dports = [t[6:] for t in f if t.startswith("dport=")]
    try:
        if len(dsts) < 2 or len(dports) < 2 or ipaddress.ip_address(dsts[0]) != dst or dports[0] != dport:
            continue
    except ValueError:
        continue
    found.append((dports[1], "unreplied" if "[UNREPLIED]" in f else "replied"))
if len(found) != 1:
    sys.exit(1)
print(*found[0])
' "$@"
}

# The table handle and the packet counters of the gateway's drop rules, from
# `nft -j list table inet fips_gateway`, as "HANDLE POOL FORWARD FORGED":
# the raw pool drop, the forward drop and the raw forged-source drop. FORGED
# is "none" when the table has no forged-source drop. Every rebuild deletes
# and recreates the table, which resets its counters and changes its handle,
# so two readings compare only when their handles agree. Fails when the
# table, the pool drop or the forward drop is missing.
drop_counters() {
    python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
entries = [e for e in doc.get("nftables", []) if isinstance(e, dict)]
tables = [e["table"] for e in entries if "table" in e]
if len(tables) != 1 or "handle" not in tables[0]:
    sys.exit(1)

def packets(rule):
    for x in rule.get("expr", []):
        if isinstance(x, dict) and isinstance(x.get("counter"), dict):
            return x["counter"].get("packets")
    return None

def has(rule, key):
    return any(isinstance(x, dict) and key in x for x in rule.get("expr", []))

def saddr_lookup(rule):
    for x in rule.get("expr", []):
        m = x.get("match") if isinstance(x, dict) else None
        if isinstance(m, dict) and m.get("left") == {"payload": {"protocol": "ip6", "field": "saddr"}} \
                and isinstance(m.get("right"), str) and m["right"].startswith("@"):
            return True
    return False

pool = forward = None
forged = "none"
for e in entries:
    r = e.get("rule")
    if not isinstance(r, dict) or not has(r, "drop"):
        continue
    if r.get("chain") == "forward":
        forward = packets(r)
    elif r.get("chain") == "raw_prerouting" and saddr_lookup(r):
        forged = packets(r)
    elif r.get("chain") == "raw_prerouting":
        pool = packets(r)
if not isinstance(pool, int) or not isinstance(forward, int) or forged is None:
    sys.exit(1)
print(tables[0]["handle"], pool, forward, forged)
'
}

# Succeeds when $1 and $2 are the same IPv6 address in any written form.
same_addr() {
    python3 -c '
import ipaddress, sys
sys.exit(0 if ipaddress.ip_address(sys.argv[1]) == ipaddress.ip_address(sys.argv[2]) else 1)
' "$@"
}

# ── Reader self-test ─────────────────────────────────────────────────────

# Run one reader on a canned input and compare its status and output with
# the expected ones. A case expecting failure also requires empty output.
# Usage: gw_case LABEL WANT_RC WANT_OUT INPUT READER [ARGS...]
gw_case() {
    local label="$1" want_rc="$2" want_out="$3" input="$4"
    shift 4
    local out rc
    if out=$("$@" <<< "$input" 2>/dev/null); then rc=0; else rc=$?; fi
    if [ "$rc" -eq "$want_rc" ] && [ "$out" = "$want_out" ]; then
        echo "  selftest $label ... OK"
        return 0
    fi
    echo "  selftest $label ... FAIL (rc $rc, output '$out'; expected rc $want_rc, output '$want_out')"
    return 1
}

# Feed every reader canned tool output and check its answers. The ip -o addr
# lines follow a capture. The ip -6 neigh show proxy and conntrack -L lines
# are verbatim output of those tools from gateway suite runs on 2026-09-23
# and 2026-09-26; an input that needs two situations at once joins lines
# from different runs. The nft, show_gateway and show_mappings inputs are
# written from the documented formats.
gw_selftest() {
    local fails=0
    local addr_eth0 addr_eth1 addr_claimed addr_at nft_lan nft_nolan

    addr_eth0='1: lo    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
2: fips0    inet6 fd3c:9a51:7e02:4b18::1/8 scope global \       valid_lft forever preferred_lft forever
2: fips0    inet6 fe80::5c2a:91ff:fe3b:1d7e/64 scope link \       valid_lft forever preferred_lft forever
40: eth0    inet6 fd02::10/64 scope global nodad \       valid_lft forever preferred_lft forever
40: eth0    inet6 fe80::42:acff:fe13:3/64 scope link \       valid_lft forever preferred_lft forever
42: eth1    inet6 fe80::42:acff:fe12:2/64 scope link \       valid_lft forever preferred_lft forever'
    addr_eth1='1: lo    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
2: fips0    inet6 fd3c:9a51:7e02:4b18::1/8 scope global \       valid_lft forever preferred_lft forever
2: fips0    inet6 fe80::5c2a:91ff:fe3b:1d7e/64 scope link \       valid_lft forever preferred_lft forever
40: eth0    inet6 fe80::42:acff:fe12:2/64 scope link \       valid_lft forever preferred_lft forever
42: eth1    inet6 fd02::10/64 scope global nodad \       valid_lft forever preferred_lft forever
42: eth1    inet6 fe80::42:acff:fe13:3/64 scope link \       valid_lft forever preferred_lft forever'
    addr_claimed='1: lo    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
40: eth0    inet6 fe80::42:acff:fe12:2/64 scope link \       valid_lft forever preferred_lft forever
42: eth1    inet6 fd02:0:0:5::10/64 scope global nodad \       valid_lft forever preferred_lft forever'
    addr_at='1: lo    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
6: eth0@if5    inet6 fe80::42:acff:fe12:2/64 scope link \       valid_lft forever preferred_lft forever
8: eth1@if7    inet6 fd02::10/64 scope global nodad \       valid_lft forever preferred_lft forever'

    gw_case "lan_iface: LAN on eth0" 0 eth0 "$addr_eth0" lan_iface fd02::10 || fails=$((fails + 1))
    gw_case "lan_iface: LAN on eth1" 0 eth1 "$addr_eth1" lan_iface fd02::10 || fails=$((fails + 1))
    gw_case "lan_iface: claimed prefix" 0 eth1 "$addr_claimed" lan_iface fd02:0:0:5::10 || fails=$((fails + 1))
    gw_case "lan_iface: first claimed /64 printed short" 0 eth0 "$addr_eth0" lan_iface fd02:0:0:0::10 || fails=$((fails + 1))
    gw_case "lan_iface: name with @ifN suffix" 0 eth1 "$addr_at" lan_iface fd02::10 || fails=$((fails + 1))
    gw_case "lan_iface: no holder" 1 "" "$addr_claimed" lan_iface fd02::10 || fails=$((fails + 1))
    gw_case "lan_iface: empty input" 1 "" "" lan_iface fd02::10 || fails=$((fails + 1))

    gw_case "gw_iface: ok response" 0 eth0 \
        '{"status":"ok","data":{"pool_cidr":"fd01::/112","lan_interface":"eth0"}}' gw_iface || fails=$((fails + 1))
    gw_case "gw_iface: error response" 1 "" \
        '{"status":"error","message":"gateway not yet initialized"}' gw_iface || fails=$((fails + 1))
    gw_case "gw_iface: empty input" 1 "" "" gw_iface || fails=$((fails + 1))

    nft_lan='table inet fips_gateway {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "eth0" meta nfproto ipv6 ip6 daddr fd01::1 dnat ip6 to fd3c:9a51:7e02:4b18::2
		iifname "fips0" meta nfproto ipv6 meta l4proto tcp tcp dport 18080 dnat ip6 to [fd02::20]:8080
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		iifname "eth0" oifname "fips0" masquerade
		meta nfproto ipv6 ip6 saddr fd3c:9a51:7e02:4b18::2 snat ip6 to fd01::1
		iifname "fips0" oifname "eth0" meta nfproto ipv6 masquerade
	}
}'
    nft_nolan=$(grep -v 'iifname "fips0" oifname' <<< "$nft_lan")
    gw_case "masq_iface: LAN masquerade on eth0" 0 eth0 "$nft_lan" masq_iface || fails=$((fails + 1))
    gw_case "masq_iface: no LAN masquerade" 1 "" "$nft_nolan" masq_iface || fails=$((fails + 1))
    gw_case "masq_iface: empty input" 1 "" "" masq_iface || fails=$((fails + 1))

    # nft_lan lists the SNAT ahead of the LAN masquerade, the order that lets
    # a mapped peer's inbound forward bypass the masquerade. nft_fixed moves
    # the masquerade ahead of it, and nft_dup adds a second SNAT for the same
    # mesh address.
    local masq_line nft_fixed nft_dup
    masq_line=$(grep 'iifname "fips0" oifname' <<< "$nft_lan")
    nft_fixed=$(awk -v m="$masq_line" '$0 == m {next} /saddr .* snat/ {print m} {print}' <<< "$nft_lan")
    nft_dup=$(awk '/saddr .* snat/ {print; sub(/fd01::1/, "fd01::2")} {print}' <<< "$nft_lan")
    gw_case "snat_before_masq: SNAT listed first" 0 1 "$nft_lan" snat_before_masq || fails=$((fails + 1))
    gw_case "snat_before_masq: masquerade listed first" 0 0 "$nft_fixed" snat_before_masq || fails=$((fails + 1))
    gw_case "snat_before_masq: no LAN masquerade" 1 "" "$nft_nolan" snat_before_masq || fails=$((fails + 1))
    gw_case "snat_before_masq: empty input" 1 "" "" snat_before_masq || fails=$((fails + 1))
    gw_case "snat_to: mesh address, short form" 0 fd01::1 "$nft_lan" \
        snat_to fd3c:9a51:7e02:4b18::2 || fails=$((fails + 1))
    gw_case "snat_to: mesh address, long form" 0 fd01::1 "$nft_lan" \
        snat_to fd3c:9a51:7e02:4b18:0:0:0:2 || fails=$((fails + 1))
    gw_case "snat_to: masquerade listed first" 0 fd01::1 "$nft_fixed" \
        snat_to fd3c:9a51:7e02:4b18::2 || fails=$((fails + 1))
    gw_case "snat_to: another mesh address" 1 "" "$nft_lan" \
        snat_to fd3c:9a51:7e02:4b18::3 || fails=$((fails + 1))
    gw_case "snat_to: two rules for one mesh address" 1 "" "$nft_dup" \
        snat_to fd3c:9a51:7e02:4b18::2 || fails=$((fails + 1))
    gw_case "snat_to: empty input" 1 "" "" snat_to fd3c:9a51:7e02:4b18::2 || fails=$((fails + 1))

    # dnat_iifs reads only the mapping DNATs, whose destination is in the
    # pool; the port-forward DNAT in nft_lan matches iifname "fips0" and is
    # not counted. nft_noiif holds a mapping DNAT without an iifname match.
    local nft_noiif nft_two
    nft_noiif=$(sed 's/iifname "eth0" meta nfproto ipv6 ip6 daddr/meta nfproto ipv6 ip6 daddr/' <<< "$nft_lan")
    nft_two=$(awk '/daddr fd01::1 dnat/ {print; sub(/fd01::1/, "fd01::2"); sub(/"eth0"/, "\"eth9\"")} {print}' <<< "$nft_lan")
    gw_case "dnat_iifs: mapping DNAT on eth0 beside a port forward" 0 eth0 "$nft_lan" \
        dnat_iifs fd01::/112 || fails=$((fails + 1))
    gw_case "dnat_iifs: mapping DNATs on two interfaces" 0 eth0,eth9 "$nft_two" \
        dnat_iifs fd01::/112 || fails=$((fails + 1))
    gw_case "dnat_iifs: mapping DNAT without iifname" 1 "" "$nft_noiif" \
        dnat_iifs fd01::/112 || fails=$((fails + 1))
    gw_case "dnat_iifs: no mapping DNAT" 1 "" "$nft_nolan" dnat_iifs fd02::/64 || fails=$((fails + 1))
    gw_case "dnat_iifs: empty input" 1 "" "" dnat_iifs fd01::/112 || fails=$((fails + 1))
    gw_case "dnat_to: virtual IP" 0 fd3c:9a51:7e02:4b18::2 "$nft_lan" \
        dnat_to fd01:0:0:0::1 || fails=$((fails + 1))
    gw_case "dnat_to: no rule" 1 "" "$nft_lan" dnat_to fd01::9 || fails=$((fails + 1))

    # The forward and raw chains as `nft -j` 1.0.9 printed a rebuild of the
    # gateway's table in a network namespace, trimmed to the two drops.
    # json_mask names the wrong ct states, and json_nolo lacks the lo
    # exemption.
    local json_ok json_mask json_nolo json_alt
    json_ok='{"nftables": [{"table": {"family": "inet", "name": "fips_gateway", "handle": 8}}, {"rule": {"family": "inet", "table": "fips_gateway", "chain": "forward", "handle": 6, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv6"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "fips0"}}, {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "eth0"}}, {"match": {"op": "!", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"counter": {"packets": 2, "bytes": 160}}, {"drop": null}]}}, {"rule": {"family": "inet", "table": "fips_gateway", "chain": "raw_prerouting", "handle": 5, "expr": [{"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "eth0"}}, {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "daddr"}}, "right": {"prefix": {"addr": "fd01::", "len": 112}}}}, {"counter": {"packets": 3, "bytes": 240}}, {"drop": null}]}}]}'
    json_mask=$(sed 's/\["established", "related"\]/["new"]/' <<< "$json_ok")
    json_nolo=$(sed 's/"right": "lo"/"right": "eth9"/' <<< "$json_ok")
    json_alt=$(sed 's/{"op": "!", "left": {"ct": {"key": "state"}}, "right": \["established", "related"\]}/{"op": "==", "left": {"\&": [{"ct": {"key": "state"}}, ["related", "established"]]}, "right": 0}/' <<< "$json_ok")
    gw_case "lan_drops_json: both drops" 0 ok "$json_ok" lan_drops_json eth0 fd01::/112 || fails=$((fails + 1))
    gw_case "lan_drops_json: mask and compare form" 0 ok "$json_alt" lan_drops_json eth0 fd01::/112 || fails=$((fails + 1))
    gw_case "lan_drops_json: wrong ct state" 1 "" "$json_mask" lan_drops_json eth0 fd01::/112 || fails=$((fails + 1))
    gw_case "lan_drops_json: no lo exemption" 1 "" "$json_nolo" lan_drops_json eth0 fd01::/112 || fails=$((fails + 1))
    gw_case "lan_drops_json: another LAN interface" 1 "" "$json_ok" lan_drops_json eth1 fd01::/112 || fails=$((fails + 1))
    gw_case "lan_drops_json: empty input" 1 "" "" lan_drops_json eth0 fd01::/112 || fails=$((fails + 1))
    gw_case "drop_counters: table without a forged-source drop" 0 "8 3 2 none" "$json_ok" \
        drop_counters || fails=$((fails + 1))
    gw_case "drop_counters: empty input" 1 "" "" drop_counters || fails=$((fails + 1))

    # The forged-source drop and the mesh-source set as `nft -j` 1.0.9
    # printed them for a rebuild in a network namespace.
    local json_forged json_forged_nolo json_both set_json
    json_forged='{"nftables": [{"table": {"family": "inet", "name": "fips_gateway", "handle": 9}}, {"rule": {"family": "inet", "table": "fips_gateway", "chain": "raw_prerouting", "handle": 7, "expr": [{"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "fips0"}}, {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": "@fips_mesh_sources"}}, {"counter": {"packets": 4, "bytes": 320}}, {"drop": null}]}}]}'
    json_forged_nolo=$(sed 's/"right": "lo"/"right": "eth9"/' <<< "$json_forged")
    json_both=$(python3 -c '
import json, sys
a, b = json.loads(sys.argv[1]), json.loads(sys.argv[2])
a["nftables"] += [e for e in b["nftables"] if "rule" in e]
print(json.dumps(a))
' "$json_ok" "$json_forged")
    set_json='{"nftables": [{"metainfo": {"version": "1.0.9"}}, {"set": {"family": "inet", "name": "fips_mesh_sources", "table": "fips_gateway", "type": "ipv6_addr", "handle": 5, "elem": ["fd02::63", "fd3c:9a51:7e02:4b18::2"]}}]}'
    gw_case "forged_drop_json: the drop" 0 ok "$json_forged" forged_drop_json || fails=$((fails + 1))
    gw_case "forged_drop_json: no lo exemption" 1 "" "$json_forged_nolo" forged_drop_json || fails=$((fails + 1))
    gw_case "forged_drop_json: empty input" 1 "" "" forged_drop_json || fails=$((fails + 1))
    gw_case "drop_counters: with a forged-source drop" 0 "8 3 2 4" "$json_both" \
        drop_counters || fails=$((fails + 1))
    gw_case "set_holds: a member, long form" 0 "" "$set_json" \
        set_holds fd3c:9a51:7e02:4b18:0:0:0:2 || fails=$((fails + 1))
    gw_case "set_holds: not a member" 1 "" "$set_json" set_holds fd02::64 || fails=$((fails + 1))
    gw_case "set_holds: empty input" 1 "" "" set_holds fd02::63 || fails=$((fails + 1))

    # conntrack -L lines in the kernel's format for a LAN client's UDP flow
    # to a virtual IP, DNAT'd and masqueraded, before and after a reply.
    local ct_udp_unreplied ct_udp_replied
    ct_udp_unreplied='udp      17 29 src=fd02::20 dst=fd01::7 sport=40000 dport=9 [UNREPLIED] src=fd3c:9a51:7e02:4b18::2 dst=fd3c:9a51:7e02:4b18::1 sport=9 dport=61234 mark=0 use=1'
    ct_udp_replied='udp      17 29 src=fd02::20 dst=fd01::7 sport=40000 dport=9 src=fd3c:9a51:7e02:4b18::2 dst=fd3c:9a51:7e02:4b18::1 sport=9 dport=61234 mark=0 use=1'
    gw_case "udp_entry: unreplied" 0 "61234 unreplied" "$ct_udp_unreplied" \
        udp_entry fd01:0:0:0::7 9 || fails=$((fails + 1))
    gw_case "udp_entry: replied" 0 "61234 replied" "$ct_udp_replied" udp_entry fd01::7 9 || fails=$((fails + 1))
    gw_case "udp_entry: another port" 1 "" "$ct_udp_replied" udp_entry fd01::7 10 || fails=$((fails + 1))
    gw_case "udp_entry: two entries" 1 "" "$ct_udp_replied"$'\n'"$ct_udp_unreplied" \
        udp_entry fd01::7 9 || fails=$((fails + 1))

    # Captured lines: one run's entries were on eth0 and a wrong-interface
    # run's on eth1. The mixed inputs join lines from the two captures, since
    # no single run holds entries on both devices.
    local nd_one0='fd01::1 dev eth0 proxy ' nd_one1='fd01::1 dev eth1 proxy '
    local nd_two1='fd01::2 dev eth1 proxy '
    gw_case "proxy_dev: captured entries on eth0" 0 eth0 \
        $'fd01::1 dev eth0 proxy \nfd01::2 dev eth0 proxy ' proxy_dev fd01::1 || fails=$((fails + 1))
    gw_case "proxy_dev: entry on eth0 after another on eth1" 0 eth0 \
        "$nd_two1"$'\n'"$nd_one0" proxy_dev fd01::1 || fails=$((fails + 1))
    gw_case "proxy_dev: no entry" 1 "" "$nd_two1" proxy_dev fd01::1 || fails=$((fails + 1))
    gw_case "proxy_dev: empty input" 1 "" "" proxy_dev fd01::1 || fails=$((fails + 1))
    gw_case "proxy_dev: entry on two devices" 1 "" \
        "$nd_one0"$'\n'"$nd_one1" proxy_dev fd01::1 || fails=$((fails + 1))

    local maps_one
    maps_one='{"status":"ok","data":{"mappings":[{"virtual_ip":"fd01::1","mesh_addr":"fd3c:9a51:7e02:4b18::2","node_addr":"0a1b2c3d4e5f60718293a4b5c6d7e8f9","dns_name":"npub1example.fips","state":"active","sessions":0,"age_secs":3,"last_ref_secs":3}]}}'
    gw_case "server_mapped: one mapping to the server" 0 1 "$maps_one" \
        server_mapped fd3c:9a51:7e02:4b18:0:0:0:2 || fails=$((fails + 1))
    gw_case "server_mapped: a mapping to another node" 0 0 "$maps_one" \
        server_mapped fd3c:9a51:7e02:4b18::3 || fails=$((fails + 1))
    gw_case "server_mapped: no mappings" 0 0 '{"status":"ok","data":{"mappings":[]}}' \
        server_mapped fd3c:9a51:7e02:4b18::2 || fails=$((fails + 1))
    gw_case "server_mapped: error response" 1 "" '{"status":"error","message":"gateway not yet initialized"}' \
        server_mapped fd3c:9a51:7e02:4b18::2 || fails=$((fails + 1))
    gw_case "server_mapped: ok response without data" 1 "" '{"status":"ok"}' \
        server_mapped fd3c:9a51:7e02:4b18::2 || fails=$((fails + 1))
    gw_case "server_mapped: empty input" 1 "" "" server_mapped fd3c:9a51:7e02:4b18::2 || fails=$((fails + 1))

    # Captured lines. ct_masq is one healthy run's whole table after the
    # probes; ct_snat is a mapping's SNAT entry and ct_unreplied a
    # wrong-interface run's entry, whose reply tuple is not rewritten.
    # ct_other is one line of ct_masq, and ct_split joins the SNAT line with
    # a masquerade line, since no single run holds both for one port.
    local srv=fda3:bc52:6504:aa72:71ca:376a:9249:ef0c
    local ct_masq ct_snat ct_unreplied ct_other ct_split ct_masq80
    ct_masq80='tcp      6 119 TIME_WAIT src=fda3:bc52:6504:aa72:71ca:376a:9249:ef0c dst=fd8d:4f49:3df7:6e1d:171e:c08d:f45f:97f3 sport=48192 dport=18080 src=fd02::20 dst=fd02::10 sport=8080 dport=48192 [ASSURED] mark=0 use=1'
    ct_other='tcp      6 119 TIME_WAIT src=fda3:bc52:6504:aa72:71ca:376a:9249:ef0c dst=fd8d:4f49:3df7:6e1d:171e:c08d:f45f:97f3 sport=48486 dport=18082 src=fd02::20 dst=fd02::10 sport=8081 dport=48486 [ASSURED] mark=0 use=1'
    ct_masq='udp      17 29 src=fda3:bc52:6504:aa72:71ca:376a:9249:ef0c dst=fd8d:4f49:3df7:6e1d:171e:c08d:f45f:97f3 sport=57965 dport=18081 src=fd02::20 dst=fd02::10 sport=8081 dport=57965 mark=0 use=1'$'\n'"$ct_masq80"$'\n'"$ct_other"
    ct_snat='tcp      6 119 TIME_WAIT src=fda3:bc52:6504:aa72:71ca:376a:9249:ef0c dst=fd8d:4f49:3df7:6e1d:171e:c08d:f45f:97f3 sport=48130 dport=18080 src=fd02::20 dst=fd01::1 sport=8080 dport=48130 [ASSURED] mark=0 use=1'
    ct_unreplied='udp      17 24 src=fda3:bc52:6504:aa72:71ca:376a:9249:ef0c dst=fd8d:4f49:3df7:6e1d:171e:c08d:f45f:97f3 sport=57286 dport=18081 [UNREPLIED] src=fd02:0:0:1::20 dst=fda3:bc52:6504:aa72:71ca:376a:9249:ef0c sport=8081 dport=57286 mark=0 use=1'
    ct_split="$ct_snat"$'\n'"$ct_masq80"
    gw_case "reply_dst: masquerade" 0 fd02::10 "$ct_masq" reply_dst tcp 18080 || fails=$((fails + 1))
    gw_case "reply_dst: mapping SNAT" 0 fd01::1 "$ct_snat" reply_dst tcp 18080 || fails=$((fails + 1))
    gw_case "reply_dst: udp, replied" 0 fd02::10 "$ct_masq" reply_dst udp 18081 || fails=$((fails + 1))
    gw_case "reply_dst: udp, unreplied, no rewrite" 0 "$srv" "$ct_unreplied" reply_dst udp 18081 || fails=$((fails + 1))
    gw_case "reply_dst: only another port's entry" 1 "" "$ct_other" reply_dst tcp 18080 || fails=$((fails + 1))
    gw_case "reply_dst: empty input" 1 "" "" reply_dst tcp 18080 || fails=$((fails + 1))
    gw_case "reply_dst: entries disagree" 1 "" "$ct_split" reply_dst tcp 18080 || fails=$((fails + 1))
    gw_case "same_addr: two forms of one address" 0 "" "" same_addr fd02:0:0:0::10 fd02::10 || fails=$((fails + 1))
    gw_case "same_addr: different addresses" 1 "" "" same_addr fd01::1 fd02::10 || fails=$((fails + 1))

    echo "  selftest: $fails case(s) failed"
    if [ "$fails" -eq 0 ]; then
        return 0
    fi
    return 1
}

if [ "${1:-}" = "selftest" ]; then
    if gw_selftest; then exit 0; else exit 1; fi
fi

if [ "${1:-}" = "inject-config" ]; then
    inject_gateway_config || exit 1
    exit 0
fi

# ── Main test ────────────────────────────────────────────────────────────

if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found. Run generate-configs.sh gateway first." >&2
    exit 1
fi

# shellcheck source=../generated-configs/npubs.env
source "$ENV_FILE"

PASSED=0
FAILED=0

check() {
    local label="$1"
    local result="$2"
    if [ "$result" -eq 0 ]; then
        echo "  $label ... OK"
        PASSED=$((PASSED + 1))
    else
        echo "  $label ... FAIL"
        FAILED=$((FAILED + 1))
    fi
}

# Record one check that the running gateway's lan_interface is the interface
# holding its LAN address, derived here from the container's addresses
# independently of the entrypoint. Sets LAN_IF to the derived name, or to
# empty when no single interface holds the address. Needs no set -e: callers
# may run it where set -e is suspended.
lan_agree() {
    local label="$1" reported="" derived=""
    for _ in $(seq 1 30); do
        if reported=$(docker exec "$GATEWAY" bash -c \
            'echo "{\"command\":\"show_gateway\"}" | nc -U -w1 /run/fips/gateway.sock 2>/dev/null' \
            | gw_iface); then
            break
        fi
        reported=""
        sleep 1
    done
    if derived=$(docker exec "$GATEWAY" ip -6 -o addr show 2>/dev/null | lan_iface "$GW_DNS"); then
        :
    else
        derived=""
    fi
    LAN_IF="$derived"
    if [ -z "$derived" ]; then
        check "$label: no single interface holds $GW_DNS" 1
    elif [ -z "$reported" ]; then
        check "$label: gateway did not report its lan_interface (derived $derived)" 1
    elif [ "$derived" != "$reported" ]; then
        check "$label: derived $derived, gateway $reported" 1
    else
        check "$label: gateway uses $derived, which holds $GW_DNS" 0
    fi
    return 0
}

# Start the LAN-side responders the inbound port forwards reach, on gw-client,
# and wait briefly for them to bind. Used by phases 8b and 8c.
gw_responders_start() {
    # Start marker HTTP servers on the LAN-side client.
    #   :8080 → "inbound-forward-ok"   (target of tcp 18080)
    #   :8081 → "inbound-forward-ok-2" (target of tcp 18082)
    # `docker exec -d` is required; `docker exec bash -c 'cmd &'` doesn't
    # keep the child alive past the exec session, even with nohup.
    docker exec "$CLIENT" sh -c '
        mkdir -p /tmp/inbound /tmp/inbound2
        echo "inbound-forward-ok"   > /tmp/inbound/index.html
        echo "inbound-forward-ok-2" > /tmp/inbound2/index.html
        pkill -f "http.server 8080" 2>/dev/null || true
        pkill -f "http.server 8081" 2>/dev/null || true
        pkill -f "udp_echo.py" 2>/dev/null || true
    ' >/dev/null 2>&1 || true
    docker exec -d "$CLIENT" python3 -m http.server 8080 --bind :: --directory /tmp/inbound \
        >/dev/null 2>&1 || true
    docker exec -d "$CLIENT" python3 -m http.server 8081 --bind :: --directory /tmp/inbound2 \
        >/dev/null 2>&1 || true

    # Start a UDP echo server on the LAN-side client at [::]:8081/udp.
    # This is the target of the udp 18081 forward. Stash the script as a
    # named file (`udp_echo.py`) so the cleanup pkill above can find it.
    docker exec "$CLIENT" sh -c 'cat > /tmp/udp_echo.py <<'\''PYEOF'\''
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("::", 8081))
while True:
    data, addr = s.recvfrom(2048)
    s.sendto(b"udp-forward-ok:" + data, addr)
PYEOF' >/dev/null 2>&1 || true
    docker exec -d "$CLIENT" python3 /tmp/udp_echo.py >/dev/null 2>&1 || true

    # Give the servers a moment to bind.
    for _ in 1 2 3 4 5; do
        TCP_READY=$(docker exec "$CLIENT" ss -6lnt 2>/dev/null | grep -cE ':8080|:8081' || true)
        UDP_READY=$(docker exec "$CLIENT" ss -6lnu 2>/dev/null | grep -c ':8081' || true)
        if [ "$TCP_READY" -ge 2 ] && [ "$UDP_READY" -ge 1 ]; then
            break
        fi
        sleep 1
    done
}

# Stop the responders gw_responders_start started.
gw_responders_stop() {
    docker exec "$CLIENT" sh -c '
        pkill -f "http.server 8080" 2>/dev/null || true
        pkill -f "http.server 8081" 2>/dev/null || true
        pkill -f "udp_echo.py" 2>/dev/null || true
    ' >/dev/null 2>&1 || true
}

echo "=== FIPS Gateway Integration Test ==="
echo ""

# Phase 0: the readers the later phases rely on, against canned input.
echo "Phase 0: Reader self-test"
if gw_selftest; then
    check "Reader self-test" 0
else
    check "Reader self-test" 1
fi
echo ""

# Phase 1: Wait for mesh convergence (gateway ↔ server, gateway ↔ server-2)
echo "Phase 1: Mesh convergence"
wait_for_peers "$GATEWAY" 2 30 || true
wait_for_peers "$SERVER" 1 30 || true
wait_for_peers "$SERVER2" 1 30 || true

# Phase 1b: LAN interface
#
# A wrong lan_interface that exists passes the gateway's startup check, and
# the LAN masquerade and the proxy NDP entries then go on the wrong interface.
# The gateway container's entrypoint derives the interface holding the LAN
# address at every container start and writes it into the gateway's config.
# This checks the result against an independent derivation from outside. An
# empty LAN_IF afterwards makes every later interface check fail.
echo ""
echo "Phase 1b: LAN interface"
LAN_IF=""
lan_agree "LAN interface"

# Phase 2: Wait for gateway DNS to respond
echo ""
echo "Phase 2: Gateway DNS readiness"
DNS_READY=false
for i in $(seq 1 30); do
    # Try resolving the server's npub via the gateway DNS from the client.
    # Match fd01:: specifically (the pool prefix) to avoid false-positive
    # matches on error messages containing fd02::10.
    local_result=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @${GW_DNS} 2>/dev/null || true)
    if echo "$local_result" | grep -q "^fd01::"; then
        echo "  Gateway DNS responding after ${i}s"
        DNS_READY=true
        break
    fi
    sleep 1
done

if [ "$DNS_READY" != true ]; then
    echo "  WARNING: Gateway DNS did not respond within 30s, continuing anyway"
fi

# The gateway names its conntrack source once at startup, before the DNS
# resolver starts, so by now the line is in the log. Ask the gateway's own
# namespace which source it should have found: the proc file when it exists,
# and otherwise the netlink dump, which the container's NET_ADMIN allows. A
# failed `docker logs` reds the check rather than counting as zero lines.
if docker exec "$GATEWAY" test -e /proc/net/nf_conntrack; then
    EXPECT_SRC=proc
else
    EXPECT_SRC=netlink
fi
if GW_START_LOG=$(docker logs "$GATEWAY" 2>&1); then
    SRC_PROC=$(grep -cF 'Conntrack source: proc; session pinning is on' <<< "$GW_START_LOG" || true)
    SRC_NETLINK=$(grep -cF 'Conntrack source: netlink; session pinning is on' <<< "$GW_START_LOG" || true)
    SRC_NONE=$(grep -cF 'No conntrack source is readable; session pinning is off' <<< "$GW_START_LOG" || true)
    case "$EXPECT_SRC" in
        proc) SRC_HIT=$SRC_PROC ;;
        *) SRC_HIT=$SRC_NETLINK ;;
    esac
    SRC_ALL=$((SRC_PROC + SRC_NETLINK + SRC_NONE))
    SRC_OK=$([ "$SRC_HIT" -eq 1 ] && [ "$SRC_ALL" -eq 1 ] && echo 0 || echo 1)
    check "Conntrack source line at startup (expect $EXPECT_SRC; proc lines $SRC_PROC, netlink lines $SRC_NETLINK, none lines $SRC_NONE)" "$SRC_OK"
else
    check "Conntrack source line at startup (docker logs failed)" 1
fi

# Phase 3: Client network setup — route virtual IP pool via gateway
echo ""
echo "Phase 3: Client network setup"
docker exec "$CLIENT" ip -6 route add fd01::/112 via ${GW_DNS} 2>/dev/null || true
echo "  Added route fd01::/112 via ${GW_DNS} on $CLIENT"
docker exec "$CLIENT2" ip -6 route add fd01::/112 via ${GW_DNS} 2>/dev/null || true
echo "  Added route fd01::/112 via ${GW_DNS} on $CLIENT2"

# Phase 4: DNS resolution test — resolve server npub from both clients,
# exercising concurrent multi-client mappings.
echo ""
echo "Phase 4: DNS resolution"
VIRTUAL_IP=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @${GW_DNS} 2>/dev/null | head -1)
if [ -n "$VIRTUAL_IP" ] && echo "$VIRTUAL_IP" | grep -q "fd01"; then
    check "Resolve ${NPUB_B:0:20}...fips on $CLIENT → $VIRTUAL_IP" 0
else
    check "Resolve ${NPUB_B:0:20}...fips on $CLIENT (got: '$VIRTUAL_IP')" 1
fi

VIRTUAL_IP_2=$(docker exec "$CLIENT2" dig +short AAAA "${NPUB_C}.fips" @${GW_DNS} 2>/dev/null | head -1)
if [ -n "$VIRTUAL_IP_2" ] && echo "$VIRTUAL_IP_2" | grep -q "fd01"; then
    check "Resolve ${NPUB_C:0:20}...fips on $CLIENT2 → $VIRTUAL_IP_2" 0
else
    check "Resolve ${NPUB_C:0:20}...fips on $CLIENT2 (got: '$VIRTUAL_IP_2')" 1
fi

# Both clients must receive distinct virtual-IP mappings — this is the
# core multi-client invariant: each LAN client gets its own pool entry.
if [ -n "$VIRTUAL_IP" ] && [ -n "$VIRTUAL_IP_2" ] && [ "$VIRTUAL_IP" != "$VIRTUAL_IP_2" ]; then
    check "Distinct virtual IPs per client ($VIRTUAL_IP vs $VIRTUAL_IP_2)" 0
else
    check "Distinct virtual IPs per client (got: '$VIRTUAL_IP' vs '$VIRTUAL_IP_2')" 1
fi

# Verify gateway show_mappings reports both client mappings. Mapping
# allocation happens in the DNS response path, but the gateway control
# socket serves a snapshot that is refreshed on a 10s tick (see
# src/bin/fips-gateway.rs tick interval). Poll up to 15s so at least
# one post-allocation snapshot tick is guaranteed to land.
ACTIVE_COUNT="error"
# Control socket protocol is line-delimited JSON ({"command": "..."});
# bare "show_mappings" returns an "invalid request" error response with
# no data field and the parse below counts that as 0 mappings.
for _ in $(seq 1 15); do
    GW_MAPPINGS=$(docker exec "$GATEWAY" bash -c \
        'echo "{\"command\":\"show_mappings\"}" | nc -U -w1 /run/fips/gateway.sock 2>/dev/null' || echo "")
    ACTIVE_COUNT=$(echo "$GW_MAPPINGS" \
        | python3 -c "import sys,json; r=json.load(sys.stdin); print(len(r.get('data',{}).get('mappings',[])))" 2>/dev/null || echo "error")
    if [ "$ACTIVE_COUNT" = "2" ]; then
        break
    fi
    sleep 1
done
if [ "$ACTIVE_COUNT" = "2" ]; then
    check "Gateway reports 2 active mappings (multi-client)" 0
else
    check "Gateway active mapping count (got: $ACTIVE_COUNT)" 1
fi

# Phase 5: End-to-end HTTP test from both clients in parallel
echo ""
echo "Phase 5: HTTP through gateway"

# Use --resolve to bind the .fips hostname to the virtual IP for curl.
# Run both client requests concurrently to exercise simultaneous flows
# through distinct NAT mappings.
RESP_FILE=$(mktemp)
RESP_FILE_2=$(mktemp)
trap 'rm -f "$RESP_FILE" "$RESP_FILE_2"' EXIT

if [ -n "$VIRTUAL_IP" ]; then
    docker exec "$CLIENT" curl -6 -s --max-time 10 \
        --resolve "${NPUB_B}.fips:8000:[$VIRTUAL_IP]" \
        "http://${NPUB_B}.fips:8000/" >"$RESP_FILE" 2>&1 &
    PID1=$!
else
    PID1=""
fi

if [ -n "$VIRTUAL_IP_2" ]; then
    docker exec "$CLIENT2" curl -6 -s --max-time 10 \
        --resolve "${NPUB_C}.fips:8000:[$VIRTUAL_IP_2]" \
        "http://${NPUB_C}.fips:8000/" >"$RESP_FILE_2" 2>&1 &
    PID2=$!
else
    PID2=""
fi

[ -n "$PID1" ] && wait "$PID1" || true
[ -n "$PID2" ] && wait "$PID2" || true

RESPONSE=$(cat "$RESP_FILE")
RESPONSE_2=$(cat "$RESP_FILE_2")

if [ -n "$VIRTUAL_IP" ]; then
    if echo "$RESPONSE" | grep -q "Fuck IPs"; then
        check "HTTP GET from $CLIENT" 0
    else
        check "HTTP GET from $CLIENT (response: '${RESPONSE:0:80}')" 1
    fi
else
    check "HTTP GET from $CLIENT (skipped — no virtual IP)" 1
fi

if [ -n "$VIRTUAL_IP_2" ]; then
    if echo "$RESPONSE_2" | grep -q "Fuck IPs"; then
        check "HTTP GET from $CLIENT2" 0
    else
        check "HTTP GET from $CLIENT2 (response: '${RESPONSE_2:0:80}')" 1
    fi
else
    check "HTTP GET from $CLIENT2 (skipped — no virtual IP)" 1
fi

# Phase 6: Verify NAT state on gateway
echo ""
echo "Phase 6: Gateway NAT state"
# Check that nftables rules were created
NFT_RULES=$(docker exec "$GATEWAY" nft list table inet fips_gateway 2>/dev/null || echo "")
if echo "$NFT_RULES" | grep -q "dnat"; then
    check "nftables DNAT rules present" 0
else
    check "nftables DNAT rules" 1
fi

# Phase 5's GET left a TCP conntrack entry to the first virtual IP, which
# stays in the table in TIME_WAIT well past two ticks. The gateway must count
# it. Poll about once a second for 25 tries, which spans two 10s ticks, and
# read the count with a parser that cannot turn a failed query into a number:
# an error response has no `data`, and the parser exits non-zero on it.
if [ -n "$VIRTUAL_IP" ]; then
    VIP_SESSIONS=error
    for _ in $(seq 1 25); do
        VIP_SESSIONS=$(docker exec "$GATEWAY" bash -c \
            'echo "{\"command\":\"show_mappings\"}" | nc -U -w1 /run/fips/gateway.sock 2>/dev/null' \
            | VIP="$VIRTUAL_IP" python3 -c "
import os, sys, json
r = json.load(sys.stdin)
data = r.get('data')
if not isinstance(data, dict) or not isinstance(data.get('mappings'), list):
    sys.exit(1)
hits = [m for m in data['mappings'] if m.get('virtual_ip') == os.environ['VIP']]
if len(hits) != 1 or not isinstance(hits[0].get('sessions'), int):
    sys.exit(1)
print(hits[0]['sessions'])
" 2>/dev/null || echo "error")
        if [ "$VIP_SESSIONS" != error ] && [ "$VIP_SESSIONS" -ge 1 ]; then
            break
        fi
        sleep 1
    done
    if [ "$VIP_SESSIONS" != error ] && [ "$VIP_SESSIONS" -ge 1 ]; then
        check "Gateway counts a session to $VIRTUAL_IP (sessions $VIP_SESSIONS, source $EXPECT_SRC)" 0
    else
        check "Gateway counts a session to $VIRTUAL_IP (sessions $VIP_SESSIONS, source $EXPECT_SRC)" 1
        echo "  Kernel conntrack entries to $VIRTUAL_IP:"
        docker exec "$GATEWAY" conntrack -L -f ipv6 -d "$VIRTUAL_IP" 2>&1 | sed 's/^/    /' || true
    fi
else
    check "Gateway counts a session (skipped — no virtual IP)" 1
fi

# The mapping's proxy neighbour entry must be on the LAN interface, or LAN
# hosts without a static route cannot reach the virtual IP. Phase 3's static
# routes bypass neighbour resolution, so nothing else would notice.
if [ -n "$VIRTUAL_IP" ] && [ -n "$LAN_IF" ] \
    && PROXY_IF=$(docker exec "$GATEWAY" ip -6 neigh show proxy 2>/dev/null | proxy_dev "$VIRTUAL_IP"); then
    if [ "$PROXY_IF" = "$LAN_IF" ]; then
        check "Proxy NDP entry for $VIRTUAL_IP on $PROXY_IF, the LAN interface" 0
    else
        check "Proxy NDP entry for $VIRTUAL_IP on $PROXY_IF, but the LAN interface is $LAN_IF" 1
    fi
else
    check "Proxy NDP entry for '$VIRTUAL_IP' on the LAN interface '$LAN_IF' (none found once)" 1
fi

# Only traffic arriving on the LAN interface is translated onto the mesh:
# every mapping DNAT and the fips0 masquerade match iifname LAN_IF, and the
# forward and raw chains drop other interfaces' traffic into fips0 and to the
# pool. The drops are read from `nft -j`, whose fields do not depend on how
# one nft version renders the ct state match.
if [ -n "$LAN_IF" ] && P6_IIFS=$(dnat_iifs fd01::/112 <<< "$NFT_RULES"); then
    if [ "$P6_IIFS" = "$LAN_IF" ]; then
        check "Mapping DNATs match iifname $LAN_IF only" 0
    else
        check "Mapping DNATs match iifname '$P6_IIFS', expected $LAN_IF" 1
    fi
else
    check "Mapping DNATs carry an iifname match (LAN '$LAN_IF', none read)" 1
fi
if [ -n "$LAN_IF" ] && grep -qE "^[[:space:]]*iifname \"$LAN_IF\" oifname \"fips0\" masquerade\$" <<< "$NFT_RULES"; then
    check "fips0 masquerade matches iifname $LAN_IF" 0
else
    check "fips0 masquerade matches iifname '$LAN_IF'" 1
fi
if [ -n "$LAN_IF" ] && P6_DROPS=$(docker exec "$GATEWAY" nft -j list table inet fips_gateway 2>/dev/null \
    | lan_drops_json "$LAN_IF" fd01::/112); then
    check "Forward drop and raw pool drop for interfaces other than $LAN_IF ($P6_DROPS)" 0
else
    check "Forward drop and raw pool drop for interfaces other than '$LAN_IF'" 1
    docker exec "$GATEWAY" nft -j list table inet fips_gateway 2>&1 | head -c 4000 | sed 's/^/    /' || true
    echo ""
fi

# Packets from a mapped mesh address are dropped unless they arrive on fips0
# or lo, and the set the drop looks up holds the live mappings' addresses.
if P6_FORGED=$(docker exec "$GATEWAY" nft -j list table inet fips_gateway 2>/dev/null | forged_drop_json); then
    check "Forged-source drop in raw_prerouting ($P6_FORGED)" 0
else
    check "Forged-source drop in raw_prerouting" 1
fi
P6_SERVER2=$(docker exec "$SERVER2" bash -c \
    "ip -6 -o addr show fips0 | awk '/inet6 fd/ {print \$4}' | cut -d/ -f1 | head -1" \
    2>/dev/null || echo "")
P6_SET_OK=1
for _ in $(seq 1 10); do
    docker exec "$CLIENT2" dig +short AAAA "${NPUB_C}.fips" @${GW_DNS} >/dev/null 2>&1 || true
    if [ -n "$P6_SERVER2" ] && docker exec "$GATEWAY" nft -j list set inet fips_gateway fips_mesh_sources \
        2>/dev/null | set_holds "$P6_SERVER2"; then
        P6_SET_OK=0
        break
    fi
    sleep 0.5
done
check "fips_mesh_sources holds $SERVER2 mesh address '$P6_SERVER2'" "$P6_SET_OK"

# Phase 6b: a reply forged from the LAN does not count as the node's
#
# gw-client opens a UDP flow to the virtual IP of gw-server's mapping, port
# 9, where nothing listens, so the entry stays unreplied. It then sends one
# datagram from gw-server's mesh address to the flow's masqueraded port on
# the gateway, as a reply would come. The gateway must drop it before
# connection tracking: the entry stays unreplied (primary), and the
# forged-source drop's counter rose (control). A rebuild between the two
# counter reads resets the counter and changes the table handle, so the
# case is retried.
echo ""
echo "Phase 6b: Forged replies from the LAN"
P6B_MESH=$(docker exec "$SERVER" bash -c \
    "ip -6 -o addr show fips0 | awk '/inet6 fd/ {print \$4}' | cut -d/ -f1 | head -1" \
    2>/dev/null || echo "")
P6B_GW=$(docker exec "$GATEWAY" bash -c \
    "ip -6 -o addr show fips0 | awk '/inet6 fd/ {print \$4}' | cut -d/ -f1 | head -1" \
    2>/dev/null || echo "")
P6B_CLIENT_IF=$(docker exec "$CLIENT" ip -6 -o addr show 2>/dev/null | lan_iface "$GW_CLIENT_LAN" || echo "")
P6B_DONE=false
if [ -z "$P6B_MESH" ] || [ -z "$P6B_GW" ] || [ -z "$P6B_CLIENT_IF" ]; then
    check "Forged reply setup (server mesh '$P6B_MESH', gateway '$P6B_GW', client interface '$P6B_CLIENT_IF')" 1
else
    for P6B_TRY in 1 2 3; do
        P6B_VIP=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @${GW_DNS} 2>/dev/null \
            | grep -m1 "^fd01::" || true)
        [ -n "$P6B_VIP" ] || { echo "  try $P6B_TRY: no virtual IP"; continue; }
        docker exec "$CLIENT" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("::", 40009))
s.sendto(b"probe", (sys.argv[1], 9))
' "$P6B_VIP" >/dev/null 2>&1 || true
        sleep 1
        P6B_ENTRY=$(docker exec "$GATEWAY" conntrack -L -f ipv6 2>/dev/null | udp_entry "$P6B_VIP" 9 || echo "")
        read -r P6B_PORT P6B_STATE <<< "$P6B_ENTRY"
        if [ "$P6B_STATE" != unreplied ]; then
            echo "  try $P6B_TRY: no unreplied entry for $P6B_VIP port 9 ('$P6B_ENTRY')"
            continue
        fi
        P6B_BEFORE=$(docker exec "$GATEWAY" nft -j list table inet fips_gateway 2>/dev/null | drop_counters || echo "")
        docker exec "$CLIENT" sh -c "
            ip -6 addr add $P6B_MESH/128 dev $P6B_CLIENT_IF nodad 2>/dev/null
            ip -6 route add $P6B_GW/128 via $GW_DNS 2>/dev/null
            true" >/dev/null 2>&1
        docker exec "$CLIENT" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 9))
s.sendto(b"forged", (sys.argv[2], int(sys.argv[3])))
' "$P6B_MESH" "$P6B_GW" "$P6B_PORT" >/dev/null 2>&1 || true
        sleep 1
        P6B_AFTER_ENTRY=$(docker exec "$GATEWAY" conntrack -L -f ipv6 2>/dev/null | udp_entry "$P6B_VIP" 9 || echo "")
        P6B_AFTER=$(docker exec "$GATEWAY" nft -j list table inet fips_gateway 2>/dev/null | drop_counters || echo "")
        docker exec "$CLIENT" sh -c "
            ip -6 route del $P6B_GW/128 via $GW_DNS 2>/dev/null
            ip -6 addr del $P6B_MESH/128 dev $P6B_CLIENT_IF 2>/dev/null
            true" >/dev/null 2>&1
        read -r P6B_H0 _ _ P6B_F0 <<< "$P6B_BEFORE"
        read -r P6B_H1 _ _ P6B_F1 <<< "$P6B_AFTER"
        if [ -z "$P6B_BEFORE" ] || [ -z "$P6B_AFTER" ] || [ "$P6B_H0" != "$P6B_H1" ]; then
            echo "  try $P6B_TRY: table rebuilt during the case ('$P6B_BEFORE' then '$P6B_AFTER'), retrying"
            continue
        fi
        P6B_DONE=true
        break
    done
    if [ "$P6B_DONE" = true ]; then
        read -r _ P6B_STATE_AFTER <<< "$P6B_AFTER_ENTRY"
        if [ "$P6B_STATE_AFTER" = unreplied ]; then
            check "A reply forged from the LAN leaves the flow to $P6B_VIP unreplied" 0
        else
            check "A reply forged from the LAN reached conntrack (entry '$P6B_AFTER_ENTRY')" 1
        fi
        if [ "$P6B_F0" != none ] && [ "$P6B_F1" -gt "$P6B_F0" ]; then
            check "The forged-source drop counted it ($P6B_F0 -> $P6B_F1)" 0
        else
            check "The forged-source drop did not count it ($P6B_F0 -> $P6B_F1)" 1
        fi
    else
        check "Forged reply case (no conclusive try in 3)" 1
    fi
fi

# Phase 6c: hosts on the gateway's other interfaces cannot use it
#
# A network namespace inside the privileged gateway container stands in for a
# host on another interface (fips-net carries no IPv6). It connects to the
# virtual IP of a live mapping and, directly, to that node's mesh address.
# Both must fail. The controls are the raw pool drop's counter for the first
# and the forward drop's for the second; every rebuild recreates the table and
# resets its counters, so a reading counts only when the table handle did not
# change across the probe, and a changed handle retries the probe.
echo ""
echo "Phase 6c: Non-LAN interfaces cannot use the gateway"
P6C_NS=gwext
SERVER2_MESH=$(docker exec "$SERVER2" bash -c \
    "ip -6 -o addr show fips0 | awk '/inet6 fd/ {print \$4}' | cut -d/ -f1 | head -1" \
    2>/dev/null || echo "")
P6C_SETUP=false
if docker exec "$GATEWAY" sh -c "
    ip netns add $P6C_NS &&
    ip link add gwext0 type veth peer name gwext1 &&
    ip link set gwext1 netns $P6C_NS &&
    ip -6 addr add fd03::1/64 dev gwext0 nodad &&
    ip link set gwext0 up &&
    ip netns exec $P6C_NS ip link set lo up &&
    ip netns exec $P6C_NS ip -6 addr add fd03::2/64 dev gwext1 nodad &&
    ip netns exec $P6C_NS ip link set gwext1 up &&
    ip netns exec $P6C_NS ip -6 route add default via fd03::1 dev gwext1
" >/dev/null 2>&1; then
    P6C_SETUP=true
fi
if [ "$P6C_SETUP" != true ] || [ -z "$SERVER2_MESH" ]; then
    check "Non-LAN namespace and $SERVER2 mesh address (setup $P6C_SETUP, mesh '$SERVER2_MESH')" 1
else
    P6C_VIP_DONE=false
    P6C_MESH_DONE=false
    for P6C_TRY in 1 2 3; do
        # Re-resolve so the probe meets a live mapping, and gate on its rules.
        P6C_VIP=$(docker exec "$CLIENT2" dig +short AAAA "${NPUB_C}.fips" @${GW_DNS} 2>/dev/null \
            | grep -m1 "^fd01::" || true)
        P6C_GATE=false
        for _ in $(seq 1 10); do
            P6C_NFT=$(docker exec "$GATEWAY" nft list table inet fips_gateway 2>/dev/null || true)
            if [ -n "$P6C_VIP" ] && P6C_TO=$(dnat_to "$P6C_VIP" <<< "$P6C_NFT") \
                && same_addr "$P6C_TO" "$SERVER2_MESH" \
                && P6C_SNAT=$(snat_to "$SERVER2_MESH" <<< "$P6C_NFT") \
                && same_addr "$P6C_SNAT" "$P6C_VIP"; then
                P6C_GATE=true
                break
            fi
            sleep 0.5
        done
        if [ "$P6C_GATE" != true ]; then
            echo "  try $P6C_TRY: no DNAT and SNAT for '$P6C_VIP' to $SERVER2_MESH"
            continue
        fi
        P6C_BEFORE=$(docker exec "$GATEWAY" nft -j list table inet fips_gateway 2>/dev/null | drop_counters || echo "")
        P6C_OUT_VIP=$(docker exec "$GATEWAY" ip netns exec $P6C_NS \
            curl -6 -s --max-time 3 "http://[$P6C_VIP]:8000/" 2>&1 || true)
        P6C_OUT_MESH=$(docker exec "$GATEWAY" ip netns exec $P6C_NS \
            curl -6 -s --max-time 3 "http://[$SERVER2_MESH]:8000/" 2>&1 || true)
        P6C_AFTER=$(docker exec "$GATEWAY" nft -j list table inet fips_gateway 2>/dev/null | drop_counters || echo "")
        read -r P6C_H0 P6C_POOL0 P6C_FWD0 _ <<< "$P6C_BEFORE"
        read -r P6C_H1 P6C_POOL1 P6C_FWD1 _ <<< "$P6C_AFTER"
        if [ -z "$P6C_BEFORE" ] || [ -z "$P6C_AFTER" ] || [ "$P6C_H0" != "$P6C_H1" ]; then
            echo "  try $P6C_TRY: table rebuilt during the probe ('$P6C_BEFORE' then '$P6C_AFTER'), retrying"
            continue
        fi
        P6C_VIP_DONE=true
        P6C_MESH_DONE=true
        break
    done
    if [ "$P6C_VIP_DONE" = true ]; then
        if ! grep -q "Fuck IPs" <<< "$P6C_OUT_VIP" && [ "$P6C_POOL1" -gt "$P6C_POOL0" ]; then
            check "Non-LAN host cannot reach $P6C_VIP (pool drop $P6C_POOL0 -> $P6C_POOL1)" 0
        else
            check "Non-LAN host reached $P6C_VIP or the pool drop did not count it (response '${P6C_OUT_VIP:0:40}', pool drop $P6C_POOL0 -> $P6C_POOL1)" 1
        fi
        if ! grep -q "Fuck IPs" <<< "$P6C_OUT_MESH" && [ "$P6C_FWD1" -gt "$P6C_FWD0" ]; then
            check "Non-LAN host cannot reach $SERVER2_MESH through fips0 (forward drop $P6C_FWD0 -> $P6C_FWD1)" 0
        else
            check "Non-LAN host reached $SERVER2_MESH or the forward drop did not count it (response '${P6C_OUT_MESH:0:40}', forward drop $P6C_FWD0 -> $P6C_FWD1)" 1
        fi
    else
        check "Non-LAN probe to a virtual IP (no conclusive try in 3)" 1
        check "Non-LAN probe to a mesh address (no conclusive try in 3)" 1
    fi
fi
docker exec "$GATEWAY" sh -c "ip link del gwext0 2>/dev/null; ip netns del $P6C_NS 2>/dev/null" \
    >/dev/null 2>&1 || true

# Phase 7: Inbound port-forward rules — UDP and a second simultaneous TCP
# forward.
#
# Three forwards configured:
#   tcp 18080 → [fd02::20]:8080  (original — single TCP rule)
#   tcp 18082 → [fd02::20]:8081  (6B — second TCP rule, multiple forwards)
#   udp 18081 → [fd02::20]:8081  (6A — UDP DNAT runtime path)
#
# Checks the DNAT rules and the LAN-side masquerade that set_port_forwards()
# installs, and that the masquerade is listed ahead of every per-mapping
# SNAT. NAT statements are terminal, so a SNAT listed first would take an
# inbound forwarded flow from that mapping's peer and the target would see a
# pool address. Phase 6's listing holds Phase 4's live mappings, so it has
# SNAT rules to order against. The traffic through the forwards is Phase
# 8b's, with no mapping to gw-server, and Phase 8c's, with one.
echo ""
echo "Phase 7: Inbound port-forward rules"

# Confirm all three port-forward DNAT rules are present on the gateway.
# The distinctive listen ports identify our rules regardless of how nft
# renders the l4proto/dport predicates.
if echo "$NFT_RULES" | grep -q "18080"; then
    check "nftables port-forward DNAT rule (tcp 18080)" 0
else
    check "nftables port-forward DNAT rule (tcp 18080)" 1
fi
if echo "$NFT_RULES" | grep -q "18082"; then
    check "nftables port-forward DNAT rule (tcp 18082)" 0
else
    check "nftables port-forward DNAT rule (tcp 18082)" 1
fi
if echo "$NFT_RULES" | grep -q "18081"; then
    check "nftables port-forward DNAT rule (udp 18081)" 0
else
    check "nftables port-forward DNAT rule (udp 18081)" 1
fi
# The LAN masquerade must name the interface Phase 1b derived. An empty
# LAN_IF or a reader that found no single rule fails, so a failed listing
# cannot pass as two empty strings.
if [ -n "$LAN_IF" ] && MASQ_IF=$(masq_iface <<< "$NFT_RULES"); then
    if [ "$MASQ_IF" = "$LAN_IF" ]; then
        check "LAN masquerade on $MASQ_IF, the LAN interface $LAN_IF" 0
    else
        check "LAN masquerade on $MASQ_IF, but the LAN interface is $LAN_IF" 1
    fi
else
    check "LAN masquerade on the LAN interface '$LAN_IF' (no single LAN masquerade rule)" 1
fi
# At least one SNAT must be listed, so an empty or reclaimed table cannot
# pass by having nothing to order.
ORDER_SNAT=$(grep -cE "saddr [0-9a-f:]+ .*snat" <<< "$NFT_RULES" || true)
if SNAT_FIRST=$(snat_before_masq <<< "$NFT_RULES"); then
    :
else
    SNAT_FIRST=error
fi
if [ "$SNAT_FIRST" = "0" ] && [ "$ORDER_SNAT" -ge 1 ]; then
    check "LAN masquerade listed ahead of all $ORDER_SNAT SNAT rules" 0
else
    check "LAN masquerade listed ahead of every SNAT rule (SNAT rules before it: $SNAT_FIRST, SNAT rules listed: $ORDER_SNAT)" 1
fi

# Phase 8: TTL expiration and pool reclamation
echo ""
echo "Phase 8: TTL expiration and pool reclamation"
# Flush conntrack so stale sessions from Phase 5 don't keep the mapping alive.
docker exec "$GATEWAY" conntrack -F 2>/dev/null || true
# Config uses ttl=5, pool_grace_period=5. Pool tick interval is 10s, so:
#   tick 1 (~10s): TTL expired → Draining (sessions=0 after flush)
#   tick 2 (~20s): grace expired → freed
# Wait 25s to ensure two full tick cycles have passed.
echo "  Waiting 25s for TTL + grace period to expire (two tick cycles)..."
sleep 25

# Query gateway control socket for mapping count.
#
# The expected value here is zero, so the reader must not be able to
# produce a zero from a failed query: an error response carries no `data`
# field, and `r.get('data',{}).get('mappings',[])` would report that as
# zero mappings and pass this check without the gateway having answered.
# The same hazard is documented at the show_mappings poll above, which is
# safe only because it waits for a positive "2". Require the key to exist
# and exit non-zero if it does not, so the `|| echo "error"` fallback
# fires and the check reds.
MAPPING_COUNT=$(docker exec "$GATEWAY" bash -c \
    'echo "{\"command\":\"show_mappings\"}" | nc -U -w1 /run/fips/gateway.sock 2>/dev/null' \
    | python3 -c "
import sys, json
r = json.load(sys.stdin)
data = r.get('data')
if not isinstance(data, dict) or not isinstance(data.get('mappings'), list):
    sys.exit(1)
print(len(data['mappings']))
" 2>/dev/null || echo "error")
if [ "$MAPPING_COUNT" = "0" ]; then
    check "Mapping reclaimed after TTL+grace" 0
else
    check "Mapping reclaimed (count: $MAPPING_COUNT)" 1
fi

# Phase 8b: Inbound port forwards through the LAN masquerade
#
# Mesh peer (gw-server) hits each gw-gateway fips0:<port> rule, which DNATs
# into the LAN-side gw-client, and the LAN masquerade rewrites the source to
# the gateway's LAN address. This is the case with no mapping to gw-server:
# it runs after Phase 8 has reclaimed the Phase 4 mapping, and the gate below
# confirms none is left. Phase 8c covers the case with a live mapping. Runs
# before Phase 9 kills the daemon.
#
# The gate reads both the control socket's mappings, a snapshot refreshed
# on the pool tick, and the kernel's table, which is what decides the rule
# that matches. A zero SNAT count needs a successful listing; Phase 11 reads
# the same pattern expecting one rule per mapping.
echo ""
echo "Phase 8b: Inbound port forwards through the LAN masquerade"
SERVER_MESH=$(docker exec "$SERVER" bash -c \
    "ip -6 -o addr show fips0 | awk '/inet6 fd/ {print \$4}' | cut -d/ -f1 | head -1" \
    2>/dev/null || echo "")
# The gateway's mesh IPv6 (the fd00::/8 address on fips0), which phases 8b and
# 8c both probe whatever 8b's gate decides.
GW_MESH_IP=$(docker exec "$GATEWAY" bash -c \
    "ip -6 -o addr show fips0 | awk '/inet6 fd/ {print \$4}' | cut -d/ -f1 | head -1" \
    2>/dev/null || echo "")
if [ -n "$SERVER_MESH" ] && SERVER_MAPS=$(docker exec "$GATEWAY" bash -c \
    'echo "{\"command\":\"show_mappings\"}" | nc -U -w1 /run/fips/gateway.sock 2>/dev/null' \
    | server_mapped "$SERVER_MESH"); then
    :
else
    SERVER_MAPS=error
fi
GATE_NFT_RC=0
GATE_NFT=$(docker exec "$GATEWAY" nft list table inet fips_gateway 2>&1) || GATE_NFT_RC=$?
GATE_SNAT=$(grep -cE "saddr [0-9a-f:]+ .*snat" <<< "$GATE_NFT" || true)
GATE_VALUES="server mesh '$SERVER_MESH', mappings to it $SERVER_MAPS, nft rc $GATE_NFT_RC, SNAT rules $GATE_SNAT"
if [ -n "$SERVER_MESH" ] && [ "$SERVER_MAPS" = "0" ] && [ "$GATE_NFT_RC" -eq 0 ] && [ "$GATE_SNAT" -eq 0 ]; then
    check "No mapping or SNAT rule to $SERVER before the probes ($GATE_VALUES)" 0
    GATE_OK=true
else
    check "No mapping or SNAT rule to $SERVER before the probes ($GATE_VALUES)" 1
    GATE_OK=false
fi

if [ "$GATE_OK" = true ]; then
    gw_responders_start

    if [ -z "$GW_MESH_IP" ]; then
        check "Gateway fips0 IPv6 address" 1
    else
        echo "  Gateway mesh IPv6: $GW_MESH_IP"

        # From the mesh side (gw-server), fetch through each TCP forward.
        FWD_RESPONSE=$(docker exec "$SERVER" curl -6 -s --max-time 10 \
            "http://[${GW_MESH_IP}]:18080/" 2>&1) || true
        # 8080 backend serves "inbound-forward-ok" (no -2 suffix) — distinct
        # from the 8081 backend so a misrouted response would be detectable.
        if echo "$FWD_RESPONSE" | grep -qE '^inbound-forward-ok$'; then
            check "Inbound HTTP via TCP forward 18080 → [${GW_CLIENT_LAN}]:8080" 0
        else
            check "Inbound HTTP via TCP forward 18080 (response: '${FWD_RESPONSE:0:80}')" 1
        fi

        FWD_RESPONSE_2=$(docker exec "$SERVER" curl -6 -s --max-time 10 \
            "http://[${GW_MESH_IP}]:18082/" 2>&1) || true
        if echo "$FWD_RESPONSE_2" | grep -q "inbound-forward-ok-2"; then
            check "Inbound HTTP via TCP forward 18082 → [${GW_CLIENT_LAN}]:8081 (6B)" 0
        else
            check "Inbound HTTP via TCP forward 18082 (response: '${FWD_RESPONSE_2:0:80}')" 1
        fi

        # 6A: UDP forward. Send a probe via a one-shot Python client on
        # gw-server; the LAN-side echo server prepends "udp-forward-ok:".
        UDP_RESPONSE=$(docker exec "$SERVER" python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b'ping-via-udp-fwd', ('${GW_MESH_IP}', 18081))
try:
    data, _ = s.recvfrom(2048)
    sys.stdout.write(data.decode('utf-8', 'replace'))
except Exception as e:
    sys.stdout.write('ERR: ' + str(e))
" 2>&1) || true
        if echo "$UDP_RESPONSE" | grep -q "udp-forward-ok:ping-via-udp-fwd"; then
            check "Inbound UDP via forward 18081 → [${GW_CLIENT_LAN}]:8081 (6A)" 0
        else
            check "Inbound UDP via forward 18081 (response: '${UDP_RESPONSE:0:80}')" 1
        fi
    fi

    # A response shows only that some rule rewrote the flow. The reply
    # destination in the gateway's conntrack entry shows which: the LAN
    # masquerade sends the reply to the gateway's LAN address, a mapping's
    # SNAT to a pool address, and no rewrite to gw-server's mesh address.
    # conntrack lists the reply tuple of an unreplied entry too.
    if CT_TABLE=$(docker exec "$GATEWAY" conntrack -L -f ipv6 2>/dev/null); then
        CT_OK=true
    else
        CT_OK=false
        CT_TABLE=""
    fi
    for fwd in tcp:18080 tcp:18082 udp:18081; do
        fwd_proto="${fwd%%:*}"
        fwd_port="${fwd#*:}"
        found=""
        if [ "$CT_OK" = true ] && found=$(reply_dst "$fwd_proto" "$fwd_port" <<< "$CT_TABLE") \
            && same_addr "$found" "$GW_DNS"; then
            check "Reply to $fwd_proto $fwd_port goes to $found, the gateway's LAN address $GW_DNS" 0
        else
            check "Reply to $fwd_proto $fwd_port goes to '$found' (conntrack read $CT_OK), expected the gateway's LAN address $GW_DNS" 1
        fi
    done

    # Stop the LAN-side responders; Phase 8c starts its own.
    gw_responders_stop
else
    check "Inbound HTTP via TCP forward 18080 (skipped: gate)" 1
    check "Inbound HTTP via TCP forward 18082 (skipped: gate)" 1
    check "Inbound UDP via forward 18081 (skipped: gate)" 1
    check "Reply to tcp 18080 goes to the gateway's LAN address (skipped: gate)" 1
    check "Reply to tcp 18082 goes to the gateway's LAN address (skipped: gate)" 1
    check "Reply to udp 18081 goes to the gateway's LAN address (skipped: gate)" 1
fi

# Phase 8c: Inbound port forward from a peer with a live mapping
#
# A LAN client resolves gw-server first, so the gateway holds a mapping and a
# SNAT rule for gw-server's mesh address, and gw-server then reaches tcp
# 18080. The LAN masquerade must still take the flow, so the reply goes to
# the gateway's LAN address, not to the mapping's pool address.
#
# Timing. On correct code the probe is masqueraded, so no conntrack entry
# names the virtual IP and nothing pins the new mapping. The pool drains it on
# the first tick more than the TTL (5s) after the dig and frees it on the next
# tick more than the grace (5s) later; with the 10s tick the rule can be gone
# about 15s after the dig. So the responders start and conntrack is flushed
# before the dig, and right after the gate a GET from gw-client to the
# virtual IP leaves an entry that names it, which pins the mapping from the
# next tick on. Only the dig, the gate poll and that GET sit inside the 15s.
# Do not add a step that can take seconds between the dig and the pin.
#
# The SNAT rule is read again after the probe. No DNS query happens in
# between, so a rule present at both ends was present during the probe;
# without that check, a mapping reclaimed early would let the reply check
# pass with no SNAT to compete with.
echo ""
echo "Phase 8c: Inbound port forward from a peer with a live mapping"
P8C_MISSING=""
[ -n "$GW_MESH_IP" ] || P8C_MISSING="gateway mesh address"
[ -n "$SERVER_MESH" ] || P8C_MISSING="${P8C_MISSING:+$P8C_MISSING and }$SERVER mesh address"
P8C_GATE=false
if [ -n "$P8C_MISSING" ]; then
    check "Mapping and SNAT rule to $SERVER before the probe (skipped: no $P8C_MISSING)" 1
else
    # Outside the window: the responders, and a flush so Phase 8b's entries
    # for tcp 18080, whose reply goes to $GW_DNS, cannot answer for this probe.
    gw_responders_start
    docker exec "$GATEWAY" conntrack -F 2>/dev/null || true

    # The window opens here.
    P8C_T0=$SECONDS
    P8C_VIP=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @${GW_DNS} 2>/dev/null \
        | grep -m1 "^fd01::" || true)
    P8C_SNAT=""
    if [ -n "$P8C_VIP" ]; then
        while :; do
            if P8C_SNAT=$(docker exec "$GATEWAY" nft list table inet fips_gateway 2>/dev/null \
                | snat_to "$SERVER_MESH") && same_addr "$P8C_SNAT" "$P8C_VIP"; then
                P8C_GATE=true
                break
            fi
            if [ $((SECONDS - P8C_T0)) -ge 5 ]; then
                break
            fi
            sleep 0.5
        done
    fi
    P8C_GATE_VALUES="dig '$P8C_VIP', SNAT target '$P8C_SNAT', $((SECONDS - P8C_T0))s after the dig"
    if [ "$P8C_GATE" = true ]; then
        check "Mapping and SNAT rule to $SERVER before the probe ($P8C_GATE_VALUES)" 0
    else
        check "Mapping and SNAT rule to $SERVER before the probe ($P8C_GATE_VALUES)" 1
    fi
fi

if [ "$P8C_GATE" = true ]; then
    # Pin the mapping: this GET's conntrack entry names the virtual IP.
    P8C_PIN=$(docker exec "$CLIENT" curl -6 -s --max-time 3 "http://[$P8C_VIP]:8000/" 2>&1) || true
    if echo "$P8C_PIN" | grep -q "Fuck IPs"; then
        check "GET from $CLIENT to $P8C_VIP pins the mapping ($((SECONDS - P8C_T0))s after the dig)" 0
    else
        check "GET from $CLIENT to $P8C_VIP pins the mapping ($((SECONDS - P8C_T0))s after the dig, response: '${P8C_PIN:0:80}')" 1
    fi

    P8C_RESPONSE=$(docker exec "$SERVER" curl -6 -s --max-time 5 \
        "http://[${GW_MESH_IP}]:18080/" 2>&1) || true
    if echo "$P8C_RESPONSE" | grep -qE '^inbound-forward-ok$'; then
        check "Inbound HTTP via TCP forward 18080 with a live mapping to $SERVER" 0
    else
        check "Inbound HTTP via TCP forward 18080 with a live mapping (response: '${P8C_RESPONSE:0:80}')" 1
    fi

    # The window closes here.
    P8C_AFTER=""
    if P8C_AFTER=$(docker exec "$GATEWAY" nft list table inet fips_gateway 2>/dev/null \
        | snat_to "$SERVER_MESH") && same_addr "$P8C_AFTER" "$P8C_VIP"; then
        check "SNAT rule to $SERVER still present after the probe ($((SECONDS - P8C_T0))s after the dig)" 0
    else
        check "SNAT rule to $SERVER gone after the probe (target '$P8C_AFTER', $((SECONDS - P8C_T0))s after the dig); the reply check below proves nothing on this run" 1
    fi

    # The probe's entry does not depend on the mapping still existing.
    P8C_FOUND=""
    if P8C_CT=$(docker exec "$GATEWAY" conntrack -L -f ipv6 2>/dev/null) \
        && P8C_FOUND=$(reply_dst tcp 18080 <<< "$P8C_CT") \
        && same_addr "$P8C_FOUND" "$GW_DNS"; then
        check "Reply to tcp 18080 with a live mapping goes to $P8C_FOUND, the gateway's LAN address $GW_DNS" 0
    else
        check "Reply to tcp 18080 with a live mapping goes to '$P8C_FOUND', expected the gateway's LAN address $GW_DNS" 1
    fi
else
    P8C_SKIP="skipped: ${P8C_MISSING:+no $P8C_MISSING}"
    [ -n "$P8C_MISSING" ] || P8C_SKIP="skipped: gate"
    check "GET from $CLIENT pins the mapping ($P8C_SKIP)" 1
    check "Inbound HTTP via TCP forward 18080 with a live mapping ($P8C_SKIP)" 1
    check "SNAT rule to $SERVER still present after the probe ($P8C_SKIP)" 1
    check "Reply to tcp 18080 with a live mapping goes to the gateway's LAN address ($P8C_SKIP)" 1
fi
if [ -z "$P8C_MISSING" ]; then
    gw_responders_stop
fi

# Phase 9: SERVFAIL when daemon DNS is down
echo ""
echo "Phase 9: SERVFAIL when daemon DNS is down"
# Kill the fips daemon inside the gateway container (gateway stays running)
docker exec "$GATEWAY" pkill -f "^fips --config" 2>/dev/null || true
sleep 2

# Gateway upstream timeout is 5s, so dig must wait longer than that.
SERVFAIL_RESULT=$(docker exec "$CLIENT" dig +short +tries=1 +time=8 AAAA "test-servfail.fips" @${GW_DNS} 2>&1 || true)
SERVFAIL_STATUS=$(docker exec "$CLIENT" dig +tries=1 +time=8 AAAA "test-servfail.fips" @${GW_DNS} 2>&1 | grep -c "SERVFAIL" || true)
if [ "$SERVFAIL_STATUS" -ge 1 ]; then
    check "SERVFAIL when daemon DNS is down" 0
else
    check "SERVFAIL when daemon DNS down (got: '${SERVFAIL_RESULT:0:80}')" 1
fi

# Phase 10: Cleanup verification (nftables removed on shutdown)
echo ""
echo "Phase 10: Cleanup on shutdown"
# fips-gateway is PID 1 (exec in entrypoint), so SIGTERM stops the container.
# Verify cleanup by checking container logs for the shutdown sequence.
docker stop --time=10 "$GATEWAY" >/dev/null 2>&1 || true
sleep 1

LOGS=$(docker logs --tail=20 "$GATEWAY" 2>&1)
if echo "$LOGS" | grep -q "shutdown complete"; then
    check "Gateway shutdown completed cleanly" 0
else
    check "Gateway shutdown (no completion message in logs)" 1
fi

# ── Long-lived gateway restart, shared by phases 11 and 12 ───────────────

# Start the stopped gateway with mappings that outlive the phase, and gate on
# its readiness. A failure is recorded through check under the label prefix
# $1 and returns 1, and the caller ends its phase. On success it sets:
#   GW_STARTED   the container's start time, for `docker logs --since`, since
#                the log still holds every earlier phase
#   GW_T0        epoch seconds at the start
#   GW_BASELINE  allocations after the readiness probe, which allocates
#   GW_PROBE     the address the readiness probe got for NPUB_B
gw_long_lived_start() {
    local prefix="$1"
    local config_file="$GENERATED_DIR/gateway/node-a.yaml"
    local expect_rev
    expect_rev=$(git -C "$SCRIPT_DIR" rev-parse --short=10 HEAD)

    # Rewrite in place (same inode): the container sees the host file through
    # a single-file bind mount, which a replace-by-rename would leave behind.
    python3 - "$config_file" <<'PYEOF'
import sys, yaml
path = sys.argv[1]
with open(path, "r+") as f:
    cfg = yaml.safe_load(f)
    cfg["gateway"]["dns"]["ttl"] = 1800
    cfg["gateway"]["pool_grace_period"] = 1800
    f.seek(0)
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
    f.truncate()
PYEOF

    docker start "$GATEWAY" >/dev/null
    GW_STARTED=$(docker inspect -f '{{.State.StartedAt}}' "$GATEWAY")
    GW_T0=$(date -u +%s)
    echo "  Gateway started at $GW_STARTED (expect rev $expect_rev)"

    local seen_ttl seen_grace
    seen_ttl=$(docker exec "$GATEWAY" grep -c "ttl: 1800" /etc/fips/fips.yaml || true)
    seen_grace=$(docker exec "$GATEWAY" grep -c "pool_grace_period: 1800" /etc/fips/fips.yaml || true)
    if [ "$seen_ttl" -ge 1 ] && [ "$seen_grace" -ge 1 ]; then
        check "$prefix: container sees ttl 1800 and grace 1800" 0
    else
        check "$prefix: container config rewrite (ttl: $seen_ttl, grace: $seen_grace)" 1
        return 1
    fi

    # Readiness is a hard gate here, unlike phases 1 and 2.
    if wait_for_peers "$GATEWAY" 2 60; then
        check "$prefix: gateway peers after restart" 0
    else
        check "$prefix: gateway peers after restart" 1
        return 1
    fi
    local probe
    GW_PROBE=""
    for _ in $(seq 1 60); do
        probe=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @${GW_DNS} 2>/dev/null || true)
        GW_PROBE=$(grep -m1 "^fd01::" <<< "$probe" || true)
        if [ -n "$GW_PROBE" ]; then
            break
        fi
        sleep 1
    done
    if [ -n "$GW_PROBE" ]; then
        check "$prefix: gateway DNS answers after restart" 0
    else
        check "$prefix: gateway DNS answers after restart" 1
        return 1
    fi

    # The entrypoint re-derives the LAN interface at this start; a mismatch
    # reds this check alone, since nothing below depends on the interface.
    lan_agree "$prefix: LAN interface after restart"

    # fips-gateway reads the entrypoint's copy, not the mounted file checked
    # above, and the checks below need its ttl and grace.
    local copy_ttl copy_grace
    copy_ttl=$(docker exec "$GATEWAY" grep -c "ttl: 1800" /etc/fips/gateway.yaml 2>/dev/null || true)
    copy_grace=$(docker exec "$GATEWAY" grep -c "pool_grace_period: 1800" /etc/fips/gateway.yaml 2>/dev/null || true)
    copy_ttl=${copy_ttl:-0}
    copy_grace=${copy_grace:-0}
    if [ "$copy_ttl" -ge 1 ] && [ "$copy_grace" -ge 1 ]; then
        check "$prefix: gateway config copy has ttl 1800 and grace 1800" 0
    else
        check "$prefix: gateway config copy (ttl: $copy_ttl, grace: $copy_grace)" 1
        return 1
    fi

    sleep 1
    local started_log rev_lines
    started_log=$(docker logs --timestamps --since "$GW_STARTED" "$GATEWAY" 2>&1)
    # The co-resident daemon logs its own "(rev ...) starting" line, so
    # anchor on the gateway's name.
    rev_lines=$(grep -cE "fips-gateway [^ ]+ \(rev ${expect_rev}\) starting" <<< "$started_log" || true)
    if [ "$rev_lines" -eq 1 ]; then
        check "$prefix: startup line reads rev ${expect_rev}) with no -dirty" 0
    else
        check "$prefix: startup line for rev ${expect_rev} (found $rev_lines)" 1
        return 1
    fi
    # The container's /var/run is not tmpfs, so the gateway keeps no pool
    # state: it must say so once at this start and still answer, which the
    # probe above showed. The cross-restart path itself needs a tmpfs and is
    # not exercised here.
    local tmpfs_warn
    # The level token sits between colour codes in the container's log.
    tmpfs_warn=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$started_log" | grep -cE " WARN .*Pool state not saved.*not on tmpfs" || true)
    if [ "$tmpfs_warn" -eq 1 ]; then
        check "$prefix: one warning that pool state is not kept off tmpfs" 0
    else
        check "$prefix: warnings that pool state is not kept off tmpfs (found $tmpfs_warn, expected 1)" 1
    fi
    GW_BASELINE=$(grep -c "Allocated virtual IP" <<< "$started_log" || true)
    return 0
}

# The pool's compiled-in admission limits. A new name is refused past
# MAPPING_CEILING live mappings, and past a burst of MAPPING_BURST new names
# are admitted at MAPPING_RATE per second, so phases that create many
# mappings retry the rate limit's refusals.
POOL_RS="$SCRIPT_DIR/../../../src/gateway/pool.rs"

# A compiled-in constant from pool.rs, or nothing if the line is not found.
pool_const() {
    sed -nE "s/^pub const $1: [a-z0-9]+ = ([0-9]+);$/\1/p" "$POOL_RS"
}

POOL_CEILING=$(pool_const MAPPING_CEILING)
POOL_BURST=$(pool_const MAPPING_BURST)
POOL_RATE=$(pool_const MAPPING_RATE)

# Per-name retry bound for the driver, in seconds: a fixed 30 s. A bound
# sized from the rate (workers x refill interval x 5) is 2 s at 10/s, shorter
# than two of the driver's 1 to 1.5 s retry pauses, and never above 20 s for
# any rate of 1/s or more; 30 s lets a name wait through many pauses. No run
# has had a name reach it. Empty when the rate could not be read, which the
# phases report.
gw_retry_bound() {
    [ -n "$POOL_RATE" ] && [ "$POOL_RATE" -gt 0 ] || return 0
    echo 30
    return 0
}

# Install the AAAA driver in the client: 4 closed-loop workers, one fresh
# socket per query, counts printed as key=value. Given a retry bound in
# seconds, a name answered SERVFAIL or not answered is asked again after a
# pause of 1 to 1.5 s until it is answered or the bound has passed since its
# first query; the exit status is 1 if any name was left unplaced. Without a
# bound each name is asked once and the exit status is 0.
gw_install_driver() {
    docker exec -i "$CLIENT" sh -c 'cat > /tmp/gw_driver.py' <<'PYEOF'
import random, socket, struct, sys, threading, time
server = sys.argv[1]
bound = float(sys.argv[2]) if len(sys.argv) > 2 else None
names = [n.strip() for n in sys.stdin if n.strip()]
lock = threading.Lock()
counts = {"answered": 0, "servfail": 0, "timeout": 0, "other": 0,
          "retries": 0, "unplaced": 0}
def query(name):
    qid = random.getrandbits(16)
    pkt = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in (name + ".fips").split("."):
        raw = label.encode()
        pkt += bytes([len(raw)]) + raw
    pkt += b"\x00" + struct.pack(">HH", 28, 1)
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.settimeout(6)
    try:
        s.sendto(pkt, (server, 53))
        while True:
            data, _ = s.recvfrom(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == qid:
                break
    except socket.timeout:
        return "timeout"
    finally:
        s.close()
    flags, _, ancount = struct.unpack(">HHH", data[2:8])
    rcode = flags & 0xF
    if rcode == 2:
        return "servfail"
    if rcode == 0 and ancount > 0:
        return "answered"
    return "other"
def place(name):
    first = time.monotonic()
    while True:
        outcome = query(name)
        with lock:
            counts[outcome] += 1
        if bound is None or outcome == "answered":
            return
        if outcome == "other" or time.monotonic() - first > bound:
            with lock:
                counts["unplaced"] += 1
            return
        with lock:
            counts["retries"] += 1
        time.sleep(1 + random.random() * 0.5)
def worker():
    while True:
        with lock:
            if not names:
                return
            name = names.pop()
        place(name)
threads = [threading.Thread(target=worker) for _ in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
print(" ".join(f"{k}={v}" for k, v in counts.items()))
sys.exit(1 if counts["unplaced"] else 0)
PYEOF
}

# Phase 11: NAT rebuild past the default netlink socket limits
#
# Every change rebuilds the whole fips_gateway table in one netlink batch.
# With the default socket buffers that batch failed from about 105 mappings
# (the acks overflowed the receive buffer, after the commit) and past about
# 313 (the batch overflowed the send buffer, and nothing was committed).
# Drive 400 new names through a gateway whose mappings outlive the phase and
# judge the result on the kernel's own table, which is what a lost rebuild
# leaves wrong, not on the daemon's debug-level success line. The names go
# through the pool's rate limit, so the driver retries its refusals. Runs
# after phase 10, so the gateway container is stopped when it starts, and it
# leaves it stopped.
echo ""
echo "Phase 11: NAT rebuild past default socket limits"

NATBIG_NAMES=400
NATBIG_CAP=180
NATBIG_SETTLE=30

natbig_now() {
    date -u +%s
}

natbig_slice() {
    NATBIG_LOG=$(docker logs --timestamps --since "$NATBIG_STARTED" "$GATEWAY" 2>&1)
}

natbig_allocated() {
    natbig_slice
    NATBIG_ALLOCATED=$(grep -c "Allocated virtual IP" <<< "$NATBIG_LOG" || true)
}

# Rules the kernel holds right now. A failed listing is recorded through
# NATBIG_RC, never read as a table with no rules.
natbig_kernel() {
    NATBIG_RC=0
    NATBIG_NFT=$(docker exec "$GATEWAY" nft list table inet fips_gateway 2>&1) || NATBIG_RC=$?
    NATBIG_DNAT=$(grep -cE "daddr fd01:[0-9a-f:]* .*dnat" <<< "$NATBIG_NFT" || true)
    NATBIG_SNAT=$(grep -cE "saddr [0-9a-f:]+ .*snat" <<< "$NATBIG_NFT" || true)
    NATBIG_MASQ=$(grep -c "masquerade" <<< "$NATBIG_NFT" || true)
}

natbig_phase() {
    gw_long_lived_start "NAT batch" || return 0
    NATBIG_STARTED="$GW_STARTED"
    local t0="$GW_T0"
    local baseline="$GW_BASELINE"
    local target=$((baseline + NATBIG_NAMES))
    echo "  Baseline allocations after readiness: $baseline; target $target"
    if [ "$baseline" -ge 1 ]; then
        check "NAT batch: readiness probe allocated (baseline $baseline)" 0
    else
        check "NAT batch: readiness probe allocated (baseline $baseline)" 1
        return 0
    fi

    # Names: real keys, since the daemon parses each one as a public key.
    local names_file have_names
    names_file=$(mktemp)
    docker exec "$GATEWAY" bash -c \
        "for i in \$(seq 1 $NATBIG_NAMES); do fipsctl keygen --stdout; done" \
        | grep '^npub1' >"$names_file" || true
    have_names=$(wc -l <"$names_file")
    if [ "$have_names" -lt "$NATBIG_NAMES" ]; then
        check "NAT batch: generated $NATBIG_NAMES names (got $have_names)" 1
        rm -f "$names_file"
        return 0
    fi

    local retry_bound
    retry_bound=$(gw_retry_bound)
    if [ -z "$retry_bound" ]; then
        check "NAT batch: MAPPING_RATE read from pool.rs ('$POOL_RATE')" 1
        rm -f "$names_file"
        return 0
    fi
    gw_install_driver
    local remaining out rc=0
    remaining=$((NATBIG_CAP - ($(natbig_now) - t0)))
    # timeout reads 0 as no limit and refuses a negative duration.
    if [ "$remaining" -le 0 ]; then
        check "NAT batch: setup exceeded ${NATBIG_CAP}s cap" 1
        rm -f "$names_file"
        return 0
    fi
    out=$(docker exec -i "$CLIENT" timeout "$remaining" \
        python3 /tmp/gw_driver.py "$GW_DNS" "$retry_bound" <"$names_file" 2>&1) || rc=$?
    rm -f "$names_file"
    echo "  [$(($(natbig_now) - t0))s] sent $NATBIG_NAMES names: $out (rc=$rc)"
    natbig_allocated
    if [ "$rc" -eq 0 ] && [ "$NATBIG_ALLOCATED" -eq "$target" ]; then
        check "NAT batch: $NATBIG_ALLOCATED live mappings allocated" 0
    else
        check "NAT batch: live mappings allocated ($NATBIG_ALLOCATED of $target, rc $rc)" 1
    fi

    # Settle on the kernel: wait until it holds a DNAT rule per allocation,
    # or the cap expires. Reaching the cap decides nothing by itself; the
    # checks below do.
    local settle=0
    natbig_kernel
    while [ "$NATBIG_DNAT" -ne "$NATBIG_ALLOCATED" ] && [ "$settle" -lt "$NATBIG_SETTLE" ]; do
        sleep 1
        settle=$((settle + 1))
        natbig_kernel
    done
    # An error logged just after the last commit still counts.
    sleep 2
    natbig_kernel
    natbig_allocated
    local nat_fail
    nat_fail=$(grep -c "Failed to add NAT rules" <<< "$NATBIG_LOG" || true)
    echo "  [$(($(natbig_now) - t0))s] allocated=$NATBIG_ALLOCATED nat_add_fail=$nat_fail" \
        "table_rc=$NATBIG_RC dnat=$NATBIG_DNAT snat=$NATBIG_SNAT masquerade=$NATBIG_MASQ settle=${settle}s"
    if [ "$nat_fail" -gt 0 ]; then
        grep "Failed to add NAT rules" <<< "$NATBIG_LOG" | sed 's/\x1b\[[0-9;]*m//g' \
            | sed -n '1p;$p' | sed 's/^/    /'
    fi

    if [ "$nat_fail" -eq 0 ]; then
        check "NAT batch: no NAT rebuild failed" 0
    else
        check "NAT batch: NAT rebuilds failed ($nat_fail)" 1
    fi
    if [ "$NATBIG_RC" -eq 0 ]; then
        check "NAT batch: nft lists the fips_gateway table" 0
    else
        check "NAT batch: nft list table failed (rc $NATBIG_RC)" 1
    fi
    if [ "$NATBIG_DNAT" -eq "$NATBIG_ALLOCATED" ] && [ "$NATBIG_SNAT" -eq "$NATBIG_ALLOCATED" ]; then
        check "NAT batch: kernel holds a DNAT and SNAT rule per mapping ($NATBIG_DNAT)" 0
    else
        check "NAT batch: kernel rules (dnat $NATBIG_DNAT, snat $NATBIG_SNAT, allocated $NATBIG_ALLOCATED)" 1
    fi
    if [ "$NATBIG_MASQ" -eq 2 ]; then
        check "NAT batch: fips0 and LAN masquerades present" 0
    else
        check "NAT batch: masquerade rules ($NATBIG_MASQ, expected 2)" 1
    fi

    docker stop --time=10 "$GATEWAY" >/dev/null 2>&1 || true
    echo "  Phase time: $(($(natbig_now) - t0))s"
}

natbig_phase

# Phase 12: Pool admission limits
#
# The pool holds at most MAPPING_CEILING live mappings, and past a burst of
# MAPPING_BURST admits new names at MAPPING_RATE per second; the constants are
# read from src/gateway/pool.rs. Restart the gateway with mappings that
# outlive the phase, make the readiness probe's mapping carry traffic, fill
# the pool to the ceiling through the rate limit with names nobody uses, then
# ask for 20 more new names: each replaces the oldest unused mapping, while
# the mapping that carries traffic is kept and still resolves. Reports rebuild
# and tick durations on the way up and the shutdown duration at the ceiling.
# Runs after phase 11, so the gateway container is stopped when it starts,
# and it leaves it stopped.
echo ""
echo "Phase 12: Pool admission limits"

LIMITS_EXTRA=20
# Sized from both trees: with the limits the fill takes about
# (ceiling - burst) / rate seconds plus retry pauses, and without them a
# measurement run reached ceiling + 20 mappings far sooner.
LIMITS_CAP=300
# Shutdown took 2.4 s at 2000 mappings in a measurement run.
LIMITS_STOP_TIME=30
limits_now() {
    date -u +%s
}

limits_slice() {
    SLICE=$(docker logs --timestamps --since "$STARTED" "$GATEWAY" 2>&1)
}

# Figures below read lines a grep on the slice has already selected, so the
# log-string guard sees each daemon-log literal. The Python matches no log
# text itself: it takes the daemon's own timestamp and key=value fields.
LIMITS_PY_FIELDS='
import re, sys, statistics
from datetime import datetime, timezone
ANSI = re.compile(r"\x1b\[[0-9;]*m")
FIELD = re.compile(r"\b(\w+)=(\S+)")
def parse(line):
    parts = ANSI.sub("", line.rstrip("\n")).split(" ", 2)
    whole, _, frac = parts[1].rstrip("Z").partition(".")
    t = datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    t = t.timestamp() + float("0." + (frac or "0"))
    return t, dict(FIELD.findall(parts[2] if len(parts) > 2 else ""))
'

limits_phase() {
    local ceiling="$POOL_CEILING" burst="$POOL_BURST" rate="$POOL_RATE"
    if [ -n "$ceiling" ] && [ -n "$burst" ] && [ -n "$rate" ] && [ "$rate" -gt 0 ] \
        && [ "$ceiling" -gt 1 ]; then
        check "Limits: read ceiling $ceiling, burst $burst, rate $rate/s from pool.rs" 0
    else
        check "Limits: constants in pool.rs (ceiling '$ceiling', burst '$burst', rate '$rate')" 1
        return 0
    fi
    local retry_bound
    retry_bound=$(gw_retry_bound)

    gw_long_lived_start "Limits" || return 0
    STARTED="$GW_STARTED"
    local t0="$GW_T0"
    local baseline="$GW_BASELINE"
    if [ "$baseline" -eq 1 ]; then
        check "Limits: the readiness probe holds the only mapping" 0
    else
        check "Limits: mappings after readiness ($baseline, expected 1)" 1
        return 0
    fi

    # The probe's mapping carries traffic: one GET through it, then wait for
    # the tick that sees the reply.
    docker exec "$CLIENT" curl -6 -s --max-time 5 "http://[$GW_PROBE]:8000/" >/dev/null 2>&1 || true
    local used_seen=1
    for _ in $(seq 1 25); do
        limits_slice
        # Field names and values are separated by colour codes in the log.
        if sed 's/\x1b\[[0-9;]*m//g' <<< "$SLICE" | grep "Mapping carried traffic" \
            | grep -qF "virtual_ip=$GW_PROBE"; then
            used_seen=0
            break
        fi
        sleep 1
    done
    check "Limits: the probe's mapping $GW_PROBE carried traffic" "$used_seen"

    # Names: real keys, since the daemon parses each one as a public key.
    local fill=$((ceiling - baseline))
    local total=$((fill + LIMITS_EXTRA))
    local names_file have_names
    names_file=$(mktemp)
    docker exec "$GATEWAY" bash -c \
        "for i in \$(seq 1 $total); do fipsctl keygen --stdout; done" \
        | grep '^npub1' >"$names_file" || true
    have_names=$(wc -l <"$names_file")
    if [ "$have_names" -lt "$total" ]; then
        check "Limits: generated $total names (got $have_names)" 1
        rm -f "$names_file"
        return 0
    fi
    gw_install_driver

    # Fill: exactly ceiling - 1 new names, each retried through the rate
    # limit's refusals. A name left unplaced, or the cap firing, fails.
    local remaining out rc=0
    remaining=$((LIMITS_CAP - ($(limits_now) - t0)))
    if [ "$remaining" -le 0 ]; then
        check "Limits: setup exceeded ${LIMITS_CAP}s cap" 1
        rm -f "$names_file"
        return 0
    fi
    out=$(sed -n "1,${fill}p" "$names_file" | docker exec -i "$CLIENT" timeout "$remaining" \
        python3 /tmp/gw_driver.py "$GW_DNS" "$retry_bound" 2>&1) || rc=$?
    echo "  [$(($(limits_now) - t0))s] fill of $fill names (retry bound ${retry_bound}s): $out (rc=$rc)"
    if [ "$rc" -eq 0 ]; then
        check "Limits: fill placed all $fill names" 0
    else
        check "Limits: fill driver failed (rc $rc)" 1
    fi
    sleep 1
    limits_slice
    local rate_refused_fill
    rate_refused_fill=$(grep -c "new-mapping rate limit reached" <<< "$SLICE" || true)

    # Past the ceiling: each name is retried through the rate limit and must
    # be answered, replacing an unused mapping.
    rc=0
    remaining=$((LIMITS_CAP - ($(limits_now) - t0)))
    if [ "$remaining" -le 0 ]; then
        check "Limits: fill exceeded ${LIMITS_CAP}s cap" 1
        rm -f "$names_file"
        return 0
    fi
    out=$(sed -n "$((fill + 1)),${total}p" "$names_file" | docker exec -i "$CLIENT" \
        timeout "$remaining" python3 /tmp/gw_driver.py "$GW_DNS" "$retry_bound" 2>&1) || rc=$?
    rm -f "$names_file"
    echo "  [$(($(limits_now) - t0))s] $LIMITS_EXTRA names past the ceiling: $out (rc=$rc)"
    local post_answered
    post_answered=$(sed -nE 's/.*answered=([0-9]+).*/\1/p' <<< "$out")
    if [ "$rc" -eq 0 ] && [ "${post_answered:-0}" -eq "$LIMITS_EXTRA" ]; then
        check "Limits: all $LIMITS_EXTRA names past the ceiling were answered" 0
    else
        check "Limits: names past the ceiling (answered '${post_answered}', rc $rc)" 1
    fi

    local probe
    probe=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @${GW_DNS} 2>/dev/null || true)
    if [ "$(grep -m1 "^fd01::" <<< "$probe" || true)" = "$GW_PROBE" ]; then
        check "Limits: NPUB_B still resolves to $GW_PROBE at the ceiling" 0
    else
        check "Limits: NPUB_B at the ceiling (got '${probe:0:60}', had $GW_PROBE)" 1
    fi

    sleep 1
    limits_slice
    local allocated reclaimed ceiling_refused rate_refused nat_fail nat_rm_fail ndp_fail evicted
    allocated=$(grep -c "Allocated virtual IP" <<< "$SLICE" || true)
    evicted=$(grep -c "Evicted never-used mapping" <<< "$SLICE" || true)
    reclaimed=$(grep -c "Reclaimed virtual IP" <<< "$SLICE" || true)
    ceiling_refused=$(grep -c "live-mapping ceiling reached" <<< "$SLICE" || true)
    rate_refused=$(grep -c "new-mapping rate limit reached" <<< "$SLICE" || true)
    nat_fail=$(grep -c "Failed to add NAT rules" <<< "$SLICE" || true)
    nat_rm_fail=$(grep -c "Failed to remove NAT rules" <<< "$SLICE" || true)
    ndp_fail=$(grep -c "Failed to add proxy NDP" <<< "$SLICE" || true)
    echo "  Slice counts: allocated=$allocated evicted=$evicted reclaimed=$reclaimed" \
        "ceiling_refused=$ceiling_refused rate_refused=$rate_refused_fill/$rate_refused" \
        "nat_add_fail=$nat_fail nat_remove_fail=$nat_rm_fail ndp_fail=$ndp_fail"
    if [ "$allocated" -eq $((ceiling + LIMITS_EXTRA)) ]; then
        check "Limits: allocations equal the ceiling plus $LIMITS_EXTRA ($allocated)" 0
    else
        check "Limits: allocations $allocated, expected $((ceiling + LIMITS_EXTRA))" 1
    fi
    if [ "$evicted" -eq "$LIMITS_EXTRA" ]; then
        check "Limits: $LIMITS_EXTRA unused mappings replaced at the ceiling" 0
    else
        check "Limits: unused mappings replaced ($evicted, expected $LIMITS_EXTRA)" 1
    fi
    local maps_json live used_probe
    maps_json=""
    for _ in $(seq 1 15); do
        maps_json=$(docker exec "$GATEWAY" bash -c \
            'echo "{\"command\":\"show_mappings\"}" | nc -U -w1 /run/fips/gateway.sock 2>/dev/null' || echo "")
        # The response for a full pool is too long for an argument.
        read -r live used_probe < <(python3 -c '
import ipaddress, json, sys
try:
    r = json.load(sys.stdin)
    ms = r["data"]["mappings"]
    probe = ipaddress.ip_address(sys.argv[1])
    used = [m.get("used") for m in ms if ipaddress.ip_address(m["virtual_ip"]) == probe]
    print(len(ms), "true" if used == [True] else "false")
except Exception:
    print("error error")
' "$GW_PROBE" <<< "$maps_json")
        [ "$live" = "$ceiling" ] && [ "$used_probe" = true ] && break
        sleep 1
    done
    if [ "$live" = "$ceiling" ] && [ "$used_probe" = true ]; then
        check "Limits: $ceiling live mappings with $GW_PROBE marked used" 0
    else
        check "Limits: show_mappings reports $live live, $GW_PROBE used '$used_probe' (expected $ceiling, true)" 1
    fi
    if [ "$allocated" -gt 0 ]; then
        if [ "$reclaimed" -eq 0 ]; then
            check "Limits: no reclaims during the phase" 0
        else
            check "Limits: reclaims during the phase ($reclaimed)" 1
        fi
    else
        check "Limits: allocations present in the slice (0)" 1
    fi
    if [ "$ceiling_refused" -eq 0 ]; then
        check "Limits: no refusal at the ceiling" 0
    else
        check "Limits: refusals at the ceiling ($ceiling_refused, expected 0)" 1
    fi
    # The rate limit must have refused during the fill, so its count is a
    # live signal for the counts above.
    if [ "$rate_refused_fill" -ge 1 ]; then
        check "Limits: the rate limit refused during the fill ($rate_refused_fill)" 0
    else
        check "Limits: rate refusals during the fill (0)" 1
    fi
    if [ $((nat_fail + nat_rm_fail + ndp_fail)) -eq 0 ]; then
        check "Limits: no NAT or proxy NDP failure lines" 0
    else
        check "Limits: failure lines (nat add $nat_fail, remove $nat_rm_fail, ndp $ndp_fail)" 1
    fi

    # Creations in any 10 s window of the fill can be at most a full burst
    # plus 10 s of refill. The bound is exact, not approximate: the bucket
    # holds at most burst whole tokens at the window's first creation and
    # gains one per 1/rate s, so one more creation needs the daemon's log
    # timestamps to lag its clock by a full token interval (100 ms at 10/s)
    # more at one end of the window than the other. Do not loosen it for skew.
    local bound=$((burst + 10 * rate)) most
    most=$(grep "Allocated virtual IP" <<< "$SLICE" | python3 -c "$LIMITS_PY_FIELDS
b, fill = int(sys.argv[1]), int(sys.argv[2])
ts = sorted(parse(l)[0] for l in sys.stdin)[b:b + fill]
most = j = 0
for i in range(len(ts)):
    while ts[i] - ts[j] > 10:
        j += 1
    most = max(most, i - j + 1)
print(most)
" "$baseline" "$fill" || true)
    if [ -n "$most" ] && [ "$most" -le "$bound" ]; then
        check "Limits: at most $most creations in any 10 s of the fill (bound $bound)" 0
    else
        check "Limits: creations in a 10 s window of the fill ('$most', bound $bound)" 1
    fi

    local added_timed tick_timed
    added_timed=$(grep "Added DNAT/SNAT rules" <<< "$SLICE" | grep -c "elapsed_us" || true)
    tick_timed=$(grep "Pool tick" <<< "$SLICE" | grep -c "tick_us" || true)
    if [ "$added_timed" -ge 1 ] && [ "$tick_timed" -ge 1 ]; then
        check "Limits: rebuild and tick timing lines present" 0
    else
        check "Limits: timing lines (rebuild $added_timed, tick $tick_timed)" 1
    fi

    echo "  --- Rebuild duration (elapsed_us over the adds in the 20 counts ending at each) ---"
    local targets=("$ceiling") rebuild_report
    [ "$ceiling" -gt 500 ] && targets=(500 "$ceiling")
    rebuild_report=$(grep "Added DNAT/SNAT rules" <<< "$SLICE" | python3 -c "$LIMITS_PY_FIELDS
by_n = {}
for l in sys.stdin:
    _, f = parse(l)
    if 'error' in f or 'elapsed_us' not in f:
        continue
    by_n[int(f['mappings'])] = int(f['elapsed_us'])
missing = 0
for t in map(int, sys.argv[1:]):
    xs = [by_n[n] for n in range(t - 19, t + 1) if n in by_n]
    if not xs:
        missing += 1
        print(f'  rebuild {t}: no successful add line with mappings in [{t - 19}, {t}]')
        continue
    print(f'  rebuild {t}: n={len(xs)} median={statistics.median(xs):.0f}us max={max(xs)}us')
print(f'REBUILD_MISSING={missing}')
" "${targets[@]}" || true)
    echo "$rebuild_report" | grep -v '^REBUILD_MISSING='
    if echo "$rebuild_report" | grep -q '^REBUILD_MISSING=0$'; then
        check "Limits: a successful add line near ${targets[*]} mappings" 0
    else
        check "Limits: a successful add line near ${targets[*]} mappings" 1
    fi

    echo "  --- Ticks as they fell ---"
    grep "Pool tick" <<< "$SLICE" | python3 -c "$LIMITS_PY_FIELDS
for l in sys.stdin:
    _, f = parse(l)
    print(f\"  tick: mappings={f.get('mappings')} read_us={f.get('read_us')} tick_us={f.get('tick_us')}\")
" || true

    echo "  --- Shutdown at the ceiling ---"
    docker stop --time="$LIMITS_STOP_TIME" "$GATEWAY" >/dev/null 2>&1 || true
    limits_slice
    local shut_lines
    shut_lines=$( { grep "fips-gateway shutting down" <<< "$SLICE"; \
        grep "fips-gateway shutdown complete" <<< "$SLICE"; } || true)
    if [ "$(echo "$shut_lines" | grep -c . || true)" -eq 2 ]; then
        echo "$shut_lines" | python3 -c "$LIMITS_PY_FIELDS
ts = [parse(l)[0] for l in sys.stdin]
print(f'  shutdown duration: {ts[1] - ts[0]:.3f}s')
" || true
        check "Limits: gateway shutdown completed within ${LIMITS_STOP_TIME}s" 0
    else
        check "Limits: gateway shutdown completion line present" 1
    fi
    echo "  Phase time: $(($(limits_now) - t0))s"
}

limits_phase

# Stops sent while fips and fips-gateway are still starting. These run their
# own containers and keep their own tally; a failure there, or a script that
# cannot run, counts as one failure here.
echo ""
echo "Start-up stop cases"
startup_rc=0
bash "$SCRIPT_DIR/startup-stop-test.sh" || startup_rc=$?
check "Start-up stop: daemon and gateway cases" "$startup_rc"

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
