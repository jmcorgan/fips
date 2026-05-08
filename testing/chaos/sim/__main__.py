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

    runner = SimRunner(scenario)
    result = runner.run()

    if result and result.panics:
        sys.exit(2)
    if runner.assertions_failed:
        sys.exit(3)
    sys.exit(0)


if __name__ == "__main__":
    main()
