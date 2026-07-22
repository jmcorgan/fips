"""CLI entry point: python -m sim <scenario.yaml>"""

import argparse
import logging
import sys

from .runner import SimRunner
from .scenario import load_scenario


def main():
    parser = argparse.ArgumentParser(
        prog="sim",
        description="FIPS stochastic network simulation",
    )
    parser.add_argument("scenario", help="Path to scenario YAML file")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Override scenario seed",
    )
    parser.add_argument(
        "--duration", type=int, default=None,
        help="Override scenario duration in seconds",
    )
    parser.add_argument(
        "--subnet", type=str, default=None,
        help="Override topology subnet CIDR (e.g. 10.30.0.0/24); node IPs "
             "derive from it. Used by CI to give each parallel run a "
             "non-overlapping network.",
    )
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        scenario = load_scenario(args.scenario)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error loading scenario: {e}", file=sys.stderr)
        sys.exit(1)

    # Apply CLI overrides
    if args.seed is not None:
        scenario.seed = args.seed
    if args.duration is not None:
        if args.duration < 1:
            print("Error: --duration must be >= 1", file=sys.stderr)
            sys.exit(1)
        scenario.duration_secs = args.duration
    if args.subnet is not None:
        scenario.topology.subnet = args.subnet

    runner = SimRunner(scenario)
    result = runner.run()

    # Liveness before content. A simulation that raised on its way up, or part
    # way through, has no panic count or assertion outcome worth reporting, and
    # saying so is more useful than whatever partial content it did produce.
    if runner.aborted:
        sys.exit(4)
    if result and result.panics:
        sys.exit(2)
    if runner.assertions_failed:
        sys.exit(3)
    sys.exit(0)


if __name__ == "__main__":
    main()
