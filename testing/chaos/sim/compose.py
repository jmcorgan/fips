"""Generate docker-compose.yml for a simulation topology."""

from __future__ import annotations

import os

from jinja2 import Template

from .scenario import Scenario
from .topology import SimTopology

# Image name for the pre-built FIPS test image.
# The runner builds this once before starting containers.
FIPS_SIM_IMAGE = "fips-test:latest"

# Jinja2 template for the compose file.
# Uses a pre-built image instead of per-service build to support large topologies.
_COMPOSE_TEMPLATE = Template(
    """\
networks:
  fips-net:
    driver: bridge
    ipam:
      config:
        - subnet: {{ subnet }}

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
    container_name: fips-node-{{ node.node_id }}
    hostname: {{ node.node_id }}
    volumes:
      - ./{{ node.node_id }}.yaml:/etc/fips/fips.yaml:ro
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
) -> str:
    """Render docker-compose.yml and write to output_dir. Returns the file path."""
    os.makedirs(output_dir, exist_ok=True)

    nodes = [topology.nodes[nid] for nid in sorted(topology.nodes)]

    content = _COMPOSE_TEMPLATE.render(
        subnet=scenario.topology.subnet,
        rust_log=scenario.logging.rust_log,
        image=FIPS_SIM_IMAGE,
        nodes=nodes,
    )

    path = os.path.join(output_dir, "docker-compose.yml")
    with open(path, "w") as f:
        f.write(content)

    return path
