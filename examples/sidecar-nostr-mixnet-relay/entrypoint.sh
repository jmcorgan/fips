#!/bin/bash
# Single-container entrypoint: generate the FIPS config, apply iptables
# isolation, start the Nostr relay (strfry + nginx), start the Nym SOCKS5
# client (only when the FIPS config enables the nym transport), and launch
# FIPS last — so the mixnet proxy is provably up before FIPS dials its peer.
set -e

# --- Generate FIPS config from environment variables ---

FIPS_NSEC="${FIPS_NSEC:?FIPS_NSEC is required}"
FIPS_UDP_BIND="${FIPS_UDP_BIND:-0.0.0.0:2121}"
FIPS_TCP_BIND="${FIPS_TCP_BIND:-0.0.0.0:8443}"
FIPS_TUN_MTU="${FIPS_TUN_MTU:-1280}"
FIPS_UDP_MTU="${FIPS_UDP_MTU:-1472}"
FIPS_PEER_TRANSPORT="${FIPS_PEER_TRANSPORT:-nym}"
FIPS_NYM_SOCKS5_ADDR="${FIPS_NYM_SOCKS5_ADDR:-127.0.0.1:1080}"
NYM_CLIENT_ID="${NYM_CLIENT_ID:-fips-nym-client}"
NYM_STARTUP_TIMEOUT="${NYM_STARTUP_TIMEOUT:-180}"

mkdir -p /etc/fips

# Build peers section
PEERS_SECTION=""
if [ -n "$FIPS_PEER_NPUB" ] && [ -n "$FIPS_PEER_ADDR" ]; then
    FIPS_PEER_ALIAS="${FIPS_PEER_ALIAS:-peer}"
    PEERS_SECTION="  - npub: \"${FIPS_PEER_NPUB}\"
    alias: \"${FIPS_PEER_ALIAS}\"
    addresses:
      - transport: ${FIPS_PEER_TRANSPORT}
        addr: \"${FIPS_PEER_ADDR}\"
    connect_policy: auto_connect"
fi

# The nym transport block is emitted only in nym mode; the SOCKS5 client
# below starts only when this block is present in the config.
NYM_SECTION=""
if [ "$FIPS_PEER_TRANSPORT" = "nym" ]; then
    NYM_SECTION="  nym:
    socks5_addr: \"${FIPS_NYM_SOCKS5_ADDR}\"
    startup_timeout_secs: 120"
fi

cat > /etc/fips/fips.yaml <<EOF
node:
  identity:
    nsec: "${FIPS_NSEC}"

tun:
  enabled: true
  name: fips0
  mtu: ${FIPS_TUN_MTU}

dns:
  enabled: true
  bind_addr: "127.0.0.1"

transports:
  udp:
    bind_addr: "${FIPS_UDP_BIND}"
    # 1472 = Docker bridge IPv4 max (1500 MTU - 8 UDP - 20 IPv4 header).
    # Override with FIPS_UDP_MTU=1280 for IPv6-min-safe deploys.
    mtu: ${FIPS_UDP_MTU}
  tcp:
    bind_addr: "${FIPS_TCP_BIND}"
${NYM_SECTION}

peers:
${PEERS_SECTION:-  []}
EOF

echo "Generated /etc/fips/fips.yaml"

# --- Start local DNS first ---
# resolv.conf points at 127.0.0.1; dnsmasq must be up before anything
# below (peer-IP resolution, harbourmaster query, nym gateway lookup).
dnsmasq

# --- Apply iptables rules for strict network isolation ---
#
# Goal: only FIPS transport traffic may use eth0. All other eth0 traffic is
# dropped. fips0 and loopback are unrestricted, so the relay (sharing this
# namespace) is reachable only over the FIPS mesh.
#
# In nym mode the direct route to the peer is explicitly DROPped before the
# general TCP accept for the mixnet gateways: if the peer comes up, the
# connection can only have travelled through the mixnet.

# IPv4: allow only FIPS transport on eth0
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o eth0 -p udp --dport 2121 -j ACCEPT
iptables -A OUTPUT -o eth0 -p udp --sport 2121 -j ACCEPT
iptables -A INPUT  -i eth0 -p udp --dport 2121 -j ACCEPT
iptables -A INPUT  -i eth0 -p udp --sport 2121 -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --dport 443 -j ACCEPT
iptables -A INPUT  -i eth0 -p tcp --sport 443 -j ACCEPT

PEER_HOST="${FIPS_PEER_ADDR%:*}"
PEER_PORT="${FIPS_PEER_ADDR##*:}"
case "$FIPS_PEER_TRANSPORT" in
    nym)
        # Block the direct path to the peer (mixnet-only proof). IPv4 only:
        # eth0 IPv6 is dropped wholesale by the ip6tables rules below.
        if [ -n "$FIPS_PEER_ADDR" ]; then
            PEER_IP=$(getent ahostsv4 "$PEER_HOST" | awk '{print $1; exit}' || true)
            if [ -n "$PEER_IP" ]; then
                iptables -A OUTPUT -o eth0 -p tcp -d "$PEER_IP" --dport "$PEER_PORT" -j DROP
                echo "Direct path to peer ${PEER_HOST} (${PEER_IP}:${PEER_PORT}) blocked — mixnet only"
            fi
        fi
        # … then allow outbound TCP for the nym client's gateway connections.
        iptables -A OUTPUT -o eth0 -p tcp -j ACCEPT
        iptables -A INPUT  -i eth0 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
        ;;
    tcp)
        # Allow dialing the peer's TCP endpoint directly, and inbound FIPS TCP.
        if [ -n "$FIPS_PEER_ADDR" ]; then
            iptables -A OUTPUT -o eth0 -p tcp --dport "$PEER_PORT" -j ACCEPT
            iptables -A INPUT  -i eth0 -p tcp --sport "$PEER_PORT" -m state --state ESTABLISHED,RELATED -j ACCEPT
        fi
        iptables -A INPUT  -i eth0 -p tcp --dport "${FIPS_TCP_BIND##*:}" -j ACCEPT
        iptables -A OUTPUT -o eth0 -p tcp --sport "${FIPS_TCP_BIND##*:}" -j ACCEPT
        ;;
esac

iptables -A OUTPUT -o eth0 -j DROP
iptables -A INPUT  -i eth0 -j DROP

# IPv6: allow fips0 and loopback, block eth0
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT  -i lo -j ACCEPT
ip6tables -A OUTPUT -o fips0 -j ACCEPT
ip6tables -A INPUT  -i fips0 -j ACCEPT
ip6tables -A OUTPUT -o eth0 -j DROP
ip6tables -A INPUT  -i eth0 -j DROP

echo "iptables isolation rules applied"

# --- Start the Nostr relay app (strfry + nginx) ---

(cd /usr/src/app && exec strfry relay) &
nginx
echo "Nostr relay started (strfry on 127.0.0.1:7777, nginx on :80)"

# --- Start the Nym SOCKS5 client (only if the config enables nym) ---

if [ "$FIPS_PEER_TRANSPORT" = "nym" ]; then
    NYM_HOST="${FIPS_NYM_SOCKS5_ADDR%:*}"
    NYM_PORT="${FIPS_NYM_SOCKS5_ADDR##*:}"

    # Auto-discover a network-requester service provider when none is set.
    if [ ! -d "${HOME}/.nym/socks5-clients/${NYM_CLIENT_ID}" ]; then
        # The provider is only consulted at init time, so auto-discovery
        # runs only when a fresh client must be initialized. Failures
        # (harbourmaster down or serving HTML) must not crash the
        # container with a bare jq error — hence the `|| true` guards
        # and the explicit empty-check below.
        if [ -z "$NYM_SERVICE_PROVIDER" ]; then
            echo "NYM_SERVICE_PROVIDER not set — querying harbourmaster.nymtech.net …"
            NYM_SERVICE_PROVIDER=$(curl -fsSL --retry 3 \
                "https://harbourmaster.nymtech.net/v2/services?order_by=routing_score&order_direction=desc&size=100" \
                2>/dev/null \
                | jq -r '[.items[] | select(.routing_score == 1.0)]
                         | sort_by(.last_updated_utc) | last
                         | .service_provider_client_id // empty' 2>/dev/null \
                || true)
            if [ -z "$NYM_SERVICE_PROVIDER" ]; then
                # Last resort: a provider known to work at the time of
                # writing (2026-06). Providers are volatile community
                # infra — if the mixnet connects but no traffic flows
                # ('no node with identity … is known' warnings), this
                # fallback has gone stale: pick a current one from
                # https://harbourmaster.nymtech.net/ and set it in .env.
                NYM_SERVICE_PROVIDER="${NYM_FALLBACK_PROVIDER:-7sfw3sEtSPwhWLmEasVmPXKxqioCo4GaXRkm9bW6yWGZ.CkhMoH85wfNcV2fwoBjc6QDbcaFZHzKqFFvXWfYMw19y@4ScsM6AVowhKTMWaH98NLntKDwbu2ZMEycUk4mZiZppG}"
                echo "WARNING: harbourmaster auto-discovery failed — using the" >&2
                echo "baked-in fallback provider (may be stale; see .env):" >&2
                echo "  ${NYM_SERVICE_PROVIDER}" >&2
            else
                echo "Auto-selected service provider: ${NYM_SERVICE_PROVIDER}"
            fi
        fi
        echo "Initializing Nym SOCKS5 client '${NYM_CLIENT_ID}' …"
        nym-socks5-client init \
            --id "${NYM_CLIENT_ID}" \
            --provider "${NYM_SERVICE_PROVIDER}" \
            --port "${NYM_PORT}" \
            --host "${NYM_HOST}"
    else
        # The provider is baked into the client state at init time — a value
        # set or discovered now does NOT apply to an existing client. Surface
        # the one actually in effect so a stale/dead provider isn't chased
        # silently (symptom: 'no node with identity … is known' warnings).
        STORED_PROVIDER=$(grep -m1 -oE '[1-9A-HJ-NP-Za-km-z]{20,}\.[1-9A-HJ-NP-Za-km-z]{20,}@[1-9A-HJ-NP-Za-km-z]{20,}' \
            "${HOME}/.nym/socks5-clients/${NYM_CLIENT_ID}/config/config.toml" 2>/dev/null || true)
        echo "Reusing existing Nym client state (provider: ${STORED_PROVIDER:-unknown})."
        echo "To switch provider, remove the nym-data volume: docker compose down -v"
    fi

    echo "Starting Nym SOCKS5 client (mixnet bootstrap may take a minute) …"
    nym-socks5-client run \
        --id "${NYM_CLIENT_ID}" \
        --port "${NYM_PORT}" \
        --host "${NYM_HOST}" &

    # FIPS must not start dialing before the proxy accepts connections.
    elapsed=0
    until nc -z "$NYM_HOST" "$NYM_PORT" 2>/dev/null; do
        if [ "$elapsed" -ge "$NYM_STARTUP_TIMEOUT" ]; then
            echo "ERROR: Nym SOCKS5 proxy not ready after ${NYM_STARTUP_TIMEOUT}s" >&2
            exit 1
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    echo "Nym SOCKS5 proxy ready at ${FIPS_NYM_SOCKS5_ADDR} (after ~${elapsed}s)"
fi

# --- Launch FIPS (container lifecycle follows the daemon) ---

echo "Starting FIPS daemon..."
exec fips --config /etc/fips/fips.yaml
