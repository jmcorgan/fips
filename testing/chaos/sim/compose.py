"""Generate docker-compose.yml for a simulation topology."""

from __future__ import annotations

import os
import re

from jinja2 import Template

from .scenario import Scenario
from .topology import SimTopology

# Image name for the pre-built FIPS test image.
#
# A harness that has already built an image passes it in FIPS_TEST_IMAGE, and
# it is then the caller's image: the runner uses it and must not rebuild it.
# Unset means a bare run, where the shared tag is the right name and the runner
# still builds it. Read at import, which is safe because the simulation always
# starts as a child process with the environment already set.
FIPS_SIM_IMAGE = os.environ.get("FIPS_TEST_IMAGE", "fips-test:latest")

# The size of each node's encrypt and decrypt worker pools. Left unset, the
# node sizes both by the host's CPU count, and each decrypt worker holds about
# 51 MiB from startup whatever the load (its bounded channel is allocated in
# full), so on the 20-CPU builder every node sat at about 1.05 GiB. Two
# nightly chaos parts whose long scenarios overlapped needed more memory than
# the host had, and the kernel's OOM killer took nodes from both runs. Pinned,
# a node holds about 0.23 GiB on any host, and no scenario's behaviour turns
# on the CPU count of the host that runs it. FIPS_ENCRYPT_WORKERS and
# FIPS_DECRYPT_WORKERS in the simulation's own environment override the
# default, for A/B runs as in testing/static/docker-compose.yml.
WORKER_ENV = ("FIPS_ENCRYPT_WORKERS", "FIPS_DECRYPT_WORKERS")
WORKERS_DEFAULT = 4

# Jinja2 template for the compose file.
# Uses a pre-built image instead of per-service build to support large topologies.
_COMPOSE_TEMPLATE = Template(
    """\
networks:
  fips-net:
    # External, and created by the sim rather than by compose. The range has to
    # be *claimed* -- attempt-create, advance on docker's own overlap error --
    # so that two concurrent runs cannot select the same one, and only the
    # process that creates the network can do that. See sim/netclaim.py.
    external: true
    name: {{ network_name }}

x-fips-common: &fips-common
  image: {{ image }}
  cap_add:
    - NET_ADMIN
    - NET_RAW
  devices:
    - /dev/net/tun:/dev/net/tun
  sysctls:
    - net.ipv6.conf.all.disable_ipv6=0
  restart: "no"
  env_file:
    - ./npubs.env
  environment:
    - RUST_LOG={{ rust_log }}
    - RUST_BACKTRACE=1
    - FIPS_TEST_MODE=chaos
{%- for name, count in workers.items() %}
    - {{ name }}={{ count }}
{%- endfor %}

services:
{% for node in nodes %}
  {{ node.node_id }}:
    <<: *fips-common
    container_name: {{ topology.container_name(node.node_id) }}
    hostname: {{ node.node_id }}
{%- if node.node_id in laned %}
    sysctls:
      - net.ipv6.conf.all.disable_ipv6=0
      - net.ipv4.conf.all.rp_filter=0
      - net.ipv4.conf.default.rp_filter=0
      - net.ipv4.conf.all.arp_ignore=0
      - net.ipv4.conf.default.arp_ignore=0
{%- endif %}
    volumes:
      - ./{{ node.node_id }}.yaml:/etc/fips/fips.yaml:ro
      - {{ resolv_conf }}:/etc/resolv.conf:ro
    networks:
      fips-net:
        ipv4_address: {{ node.docker_ip }}
{% endfor %}
"""
)


def worker_counts() -> dict[str, int]:
    """Each worker-pool variable and the count every node is given.

    An override that is not a count is refused here rather than passed on:
    the node reads one it cannot parse as unset, which would quietly bring
    back the CPU-count default.
    """
    counts = {}
    for name in WORKER_ENV:
        raw = os.environ.get(name, "").strip()
        if not raw:
            counts[name] = WORKERS_DEFAULT
        elif re.fullmatch(r"[0-9]+", raw):
            counts[name] = int(raw)
        else:
            raise ValueError(f"{name}={raw!r} is not a worker count")
    return counts


def generate_compose(
    topology: SimTopology,
    scenario: Scenario,
    output_dir: str,
    network_name: str,
) -> str:
    """Render docker-compose.yml and write to output_dir. Returns the file path.

    ``network_name`` is the docker network the sim has already claimed; the
    compose file refers to it as external rather than declaring a subnet, so
    that the claim and the creation are the same operation.
    """
    os.makedirs(output_dir, exist_ok=True)

    nodes = [topology.nodes[nid] for nid in sorted(topology.nodes)]
    # The ends of a laned edge accept a frame on any lane for any address
    # in their namespace and answer ARP for it; set here, so the result
    # does not depend on the host's defaults.
    laned = {n for edge in topology.edge_lanes for n in edge}

    # Absolute path to the shared resolv.conf (bind-mounted into containers
    # so Docker's runtime resolv.conf generation doesn't overwrite it).
    resolv_conf = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "docker", "resolv.conf")
    )

    content = _COMPOSE_TEMPLATE.render(
        network_name=network_name,
        rust_log=scenario.logging.rust_log,
        image=FIPS_SIM_IMAGE,
        nodes=nodes,
        resolv_conf=resolv_conf,
        topology=topology,
        laned=laned,
        workers=worker_counts(),
    )

    path = os.path.join(output_dir, "docker-compose.yml")
    with open(path, "w") as f:
        f.write(content)

    return path
