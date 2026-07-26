"""Generate docker-compose.yml for a simulation topology."""

from __future__ import annotations

import os

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

services:
{% for node in nodes %}
  {{ node.node_id }}:
    <<: *fips-common
    container_name: {{ topology.container_name(node.node_id) }}
    hostname: {{ node.node_id }}
    volumes:
      - ./{{ node.node_id }}.yaml:/etc/fips/fips.yaml:ro
      - {{ resolv_conf }}:/etc/resolv.conf:ro
    networks:
      fips-net:
        ipv4_address: {{ node.docker_ip }}
{% endfor %}
"""
)


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
    )

    path = os.path.join(output_dir, "docker-compose.yml")
    with open(path, "w") as f:
        f.write(content)

    return path
