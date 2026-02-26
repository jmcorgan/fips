"""Main simulation orchestration."""

from __future__ import annotations

import json
import logging
import os
import random
import signal
import sys
import time

from .compose import generate_compose
from .config_gen import write_configs
from .control import snapshot_all_mmp, snapshot_all_trees
from .docker_exec import docker_compose
from .links import LinkManager
from .logs import AnalysisResult, analyze_logs, collect_logs, write_sim_metadata
from .netem import NetemManager
from .nodes import NodeManager
from .scenario import Scenario
from .topology import SimTopology, generate_topology
from .traffic import TrafficManager
from .veth import VethManager

log = logging.getLogger(__name__)


class SimRunner:
    def __init__(self, scenario: Scenario):
        self.scenario = scenario
        self.rng = random.Random(scenario.seed)
        self.topology: SimTopology | None = None
        self.compose_file: str | None = None
        self.output_dir: str = scenario.logging.output_dir
        self._interrupted = False

        # Shared set of currently-down node IDs (updated by NodeManager,
        # read by NetemManager, LinkManager, TrafficManager)
        self._down_nodes: set[str] = set()

        # Managers (initialized during setup)
        self.veth_mgr: VethManager | None = None
        self.netem_mgr: NetemManager | None = None
        self.link_mgr: LinkManager | None = None
        self.traffic_mgr: TrafficManager | None = None
        self.node_mgr: NodeManager | None = None

    def run(self) -> AnalysisResult | None:
        """Run the full simulation lifecycle."""
        signal.signal(signal.SIGINT, self._handle_sigint)
        signal.signal(signal.SIGTERM, self._handle_sigint)

        result = None
        try:
            self._setup()
            self._warmup()
            self._simulation_loop()
        except Exception:
            log.exception("Simulation failed")
        finally:
            result = self._teardown()

        return result

    def _handle_sigint(self, signum, frame):
        if self._interrupted:
            log.warning("Force exit")
            sys.exit(1)
        log.info("Interrupt received, shutting down gracefully...")
        self._interrupted = True

    def _setup(self):
        """Generate topology, configs, compose file. Start containers."""
        s = self.scenario
        mesh_name = f"sim-{s.name}-{s.seed}"

        # Set up runner log file so all sim orchestration output is captured
        # alongside the per-node FIPS logs for post-run analysis.
        os.makedirs(self.output_dir, exist_ok=True)
        runner_log_path = os.path.join(self.output_dir, "runner.log")
        fh = logging.FileHandler(runner_log_path, mode="w")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-5s %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        ))
        logging.getLogger().addHandler(fh)
        log.info("Runner log: %s", runner_log_path)

        # 1. Generate topology
        log.info(
            "Generating %d-node %s topology (seed=%d)...",
            s.topology.num_nodes,
            s.topology.algorithm,
            s.seed,
        )
        self.topology = generate_topology(s.topology, self.rng, mesh_name)
        log.info(
            "Topology: %d nodes, %d edges",
            len(self.topology.nodes),
            len(self.topology.edges),
        )

        # Log adjacency summary
        for nid in sorted(self.topology.nodes):
            peers = sorted(self.topology.nodes[nid].peers)
            log.info("  %s: peers=%s", nid, ",".join(peers))

        # 2. Generate configs
        docker_network_dir = os.path.join(os.path.dirname(__file__), "..")
        config_dir = os.path.normpath(
            os.path.join(docker_network_dir, "generated-configs", "sim")
        )
        write_configs(self.topology, config_dir, self.scenario.fips_overrides)
        log.info("Wrote node configs to %s", config_dir)

        # 3. Generate docker-compose.yml
        self.compose_file = generate_compose(self.topology, self.scenario, config_dir)
        log.info("Wrote %s", self.compose_file)

        # 4. Build images (reuses Docker cache)
        log.info("Building Docker images...")
        docker_compose(self.compose_file, ["build"])

        # 5. Start containers
        log.info("Starting %d containers...", len(self.topology.nodes))
        docker_compose(self.compose_file, ["up", "-d"])

        # 6. Set up veth pairs for Ethernet edges (before netem)
        #
        # The entrypoint script waits for configured Ethernet interfaces
        # to appear before starting FIPS, so we just need to create the
        # veth pairs promptly after containers are running.
        if self.topology.has_ethernet():
            self.veth_mgr = VethManager(self.topology)
            log.info("Setting up Ethernet veth pairs...")
            self.veth_mgr.setup_all()

        # 7. Initialize managers
        if s.netem.enabled:
            bw = s.bandwidth if s.bandwidth.enabled else None
            self.netem_mgr = NetemManager(self.topology, s.netem, self.rng, bandwidth=bw)
            self.netem_mgr.down_nodes = self._down_nodes
            log.info("Applying initial per-link netem...")
            self.netem_mgr.setup_initial()

        if s.link_flaps.enabled:
            self.link_mgr = LinkManager(
                self.topology, s.link_flaps, self.rng, netem_mgr=self.netem_mgr
            )

        if s.traffic.enabled:
            self.traffic_mgr = TrafficManager(
                self.topology, s.traffic, self.rng, down_nodes=self._down_nodes
            )

        if s.node_churn.enabled:
            self.node_mgr = NodeManager(
                self.topology, s.node_churn, self.rng,
                netem_mgr=self.netem_mgr, down_nodes=self._down_nodes,
                veth_mgr=self.veth_mgr,
            )

    def _warmup(self):
        """Wait for mesh convergence."""
        n = len(self.topology.nodes)
        wait = max(10, n)  # Heuristic: ~1s per node, minimum 10s
        log.info("Waiting %ds for mesh convergence...", wait)
        self._sleep(wait)
        self._take_snapshot("warmup")

    def _simulation_loop(self):
        """Main event loop driving stochastic behavior."""
        start = time.time()
        s = self.scenario
        duration = s.duration_secs
        log.info("Simulation running for %ds...", duration)

        # Schedule first events
        next_netem = self._schedule_next(start, s.netem.mutation.interval_secs) if self.netem_mgr else float("inf")
        next_flap = self._schedule_next(start, s.link_flaps.interval_secs) if self.link_mgr else float("inf")
        next_traffic = self._schedule_next(start, s.traffic.interval_secs) if self.traffic_mgr else float("inf")
        next_churn = self._schedule_next(start, s.node_churn.interval_secs) if self.node_mgr else float("inf")

        while not self._interrupted:
            now = time.time()
            elapsed = now - start
            if elapsed >= duration:
                break

            # Netem mutation
            if self.netem_mgr and now >= next_netem:
                self.netem_mgr.mutate()
                next_netem = self._schedule_next(now, s.netem.mutation.interval_secs)

            # Link flaps
            if self.link_mgr:
                if now >= next_flap:
                    self.link_mgr.maybe_flap()
                    next_flap = self._schedule_next(now, s.link_flaps.interval_secs)
                self.link_mgr.restore_expired()

            # Traffic generation
            if self.traffic_mgr:
                if now >= next_traffic:
                    self.traffic_mgr.maybe_spawn()
                    next_traffic = self._schedule_next(now, s.traffic.interval_secs)
                self.traffic_mgr.cleanup_expired()

            # Node churn
            if self.node_mgr:
                if now >= next_churn:
                    self.node_mgr.maybe_kill()
                    next_churn = self._schedule_next(now, s.node_churn.interval_secs)
                self.node_mgr.restore_expired()

            # Status line
            down_links = self.link_mgr.down_count if self.link_mgr else 0
            down_nodes = self.node_mgr.down_count if self.node_mgr else 0
            active = self.traffic_mgr.active_count if self.traffic_mgr else 0
            print(
                f"\r  [{elapsed:.0f}s/{duration}s] "
                f"nodes={len(self.topology.nodes)} "
                f"edges={len(self.topology.edges)} "
                f"links_down={down_links} "
                f"nodes_down={down_nodes} "
                f"traffic={active}   ",
                end="",
                flush=True,
            )

            self._sleep(1)

        print()  # Clear status line

    def _teardown(self) -> AnalysisResult | None:
        """Stop dynamic elements, collect logs, analyze, stop containers."""
        result = None

        if self.topology and self.compose_file:
            # Stop traffic
            if self.traffic_mgr:
                log.info("Stopping traffic sessions...")
                self.traffic_mgr.stop_all()

            # Restore links
            if self.link_mgr:
                log.info("Restoring downed links...")
                self.link_mgr.restore_all()

            # Restore stopped nodes (needed for snapshots and log collection)
            if self.node_mgr:
                log.info("Restoring stopped nodes...")
                self.node_mgr.restore_all()

            # Take final tree snapshot while nodes are still running
            self._take_snapshot("final")

            # Collect logs before stopping containers
            container_names = [
                self.topology.container_name(nid) for nid in sorted(self.topology.nodes)
            ]
            log.info("Collecting logs from %d containers...", len(container_names))
            logs = collect_logs(container_names, self.output_dir)

            # Analyze
            result = analyze_logs(logs)
            analysis_path = os.path.join(self.output_dir, "analysis.txt")
            with open(analysis_path, "w") as f:
                f.write(result.summary())
            print(result.summary())

            # Write metadata
            write_sim_metadata(
                self.output_dir,
                scenario_name=self.scenario.name,
                seed=self.scenario.seed,
                num_nodes=len(self.topology.nodes),
                num_edges=len(self.topology.edges),
                duration_secs=self.scenario.duration_secs,
                topology=self.topology,
            )

            # Clean up veth pairs
            if self.veth_mgr:
                log.info("Cleaning up veth pairs...")
                self.veth_mgr.teardown_all()

            # Stop containers
            log.info("Stopping containers...")
            docker_compose(
                self.compose_file,
                ["down"],
                check=False,
            )

        return result

    def _take_snapshot(self, label: str):
        """Query all nodes via control socket and save tree/MMP snapshots."""
        if not self.topology:
            return
        log.info("Taking %s snapshot...", label)
        tree_snap = snapshot_all_trees(self.topology)
        mmp_snap = snapshot_all_mmp(self.topology)

        tree_path = os.path.join(self.output_dir, f"tree-snapshot-{label}.json")
        mmp_path = os.path.join(self.output_dir, f"mmp-snapshot-{label}.json")
        os.makedirs(self.output_dir, exist_ok=True)
        with open(tree_path, "w") as f:
            json.dump(tree_snap, f, indent=2)
        with open(mmp_path, "w") as f:
            json.dump(mmp_snap, f, indent=2)
        log.info(
            "Snapshot %s: %d/%d tree, %d/%d mmp responses",
            label,
            len(tree_snap),
            len(self.topology.nodes),
            len(mmp_snap),
            len(self.topology.nodes),
        )

    def _schedule_next(self, now: float, interval) -> float:
        """Schedule the next event using a Range interval."""
        return now + self.rng.uniform(interval.min, interval.max)

    def _sleep(self, seconds: float):
        """Sleep in small increments so SIGINT can break out."""
        end = time.time() + seconds
        while time.time() < end and not self._interrupted:
            time.sleep(min(0.5, end - time.time()))
