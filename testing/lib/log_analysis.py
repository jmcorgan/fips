#!/usr/bin/env python3
"""Shared log analysis for FIPS integration tests.

Parses structured tracing output from FIPS daemons and categorizes
events (panics, errors, sessions, parent switches, etc.).

CLI usage:
    python3 -m lib.log_analysis <logfile> [<logfile> ...]
    python3 -m lib.log_analysis --from-docker <container> [<container> ...]

Exit codes:
    0 — no panics detected
    2 — panics detected
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass, field


# Regex to strip ANSI escape codes from tracing output
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return ANSI_RE.sub("", text)


@dataclass
class AnalysisResult:
    """Categorized events extracted from FIPS daemon logs."""

    errors: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[tuple[str, str]] = field(default_factory=list)
    sessions_established: list[tuple[str, str]] = field(default_factory=list)
    peers_promoted: list[tuple[str, str]] = field(default_factory=list)
    peer_removals: list[tuple[str, str]] = field(default_factory=list)
    parent_switches: list[tuple[str, str]] = field(default_factory=list)
    mmp_link_metrics: list[tuple[str, str]] = field(default_factory=list)
    mmp_session_metrics: list[tuple[str, str]] = field(default_factory=list)
    handshake_timeouts: list[tuple[str, str]] = field(default_factory=list)
    panics: list[tuple[str, str]] = field(default_factory=list)
    congestion_detected: list[tuple[str, str]] = field(default_factory=list)
    kernel_drop_events: list[tuple[str, str]] = field(default_factory=list)
    rekey_cutovers: list[tuple[str, str]] = field(default_factory=list)
    discovery_initiated: list[tuple[str, str]] = field(default_factory=list)
    discovery_succeeded: list[tuple[str, str]] = field(default_factory=list)
    discovery_bloom_miss: list[tuple[str, str]] = field(default_factory=list)
    discovery_backoff: list[tuple[str, str]] = field(default_factory=list)
    discovery_dedup: list[tuple[str, str]] = field(default_factory=list)
    discovery_timeout: list[tuple[str, str]] = field(default_factory=list)
    discovery_retry: list[tuple[str, str]] = field(default_factory=list)
    discovery_no_tree_peer: list[tuple[str, str]] = field(default_factory=list)
    discovery_fallback: list[tuple[str, str]] = field(default_factory=list)
    discovery_trigger: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        """Format a human-readable summary of the analysis."""
        lines = [
            "=== Log Analysis ===",
            "",
            f"Panics:               {len(self.panics)}",
            f"Errors:               {len(self.errors)}",
            f"Warnings:             {len(self.warnings)}",
            f"Sessions established:  {len(self.sessions_established)}",
            f"Peers promoted:        {len(self.peers_promoted)}",
            f"Peer removals:         {len(self.peer_removals)}",
            f"Parent switches:       {len(self.parent_switches)}",
            f"Handshake timeouts:    {len(self.handshake_timeouts)}",
            f"MMP link samples:      {len(self.mmp_link_metrics)}",
            f"MMP session samples:   {len(self.mmp_session_metrics)}",
            f"Congestion events:     {len(self.congestion_detected)}",
            f"Kernel drop events:    {len(self.kernel_drop_events)}",
            f"Rekey cutovers:        {len(self.rekey_cutovers)}",
            "",
            "--- Discovery ---",
            f"Triggers:              {len(self.discovery_trigger)}",
            f"Initiated:             {len(self.discovery_initiated)}",
            f"Succeeded:             {len(self.discovery_succeeded)}",
            f"Retries:               {len(self.discovery_retry)}",
            f"Bloom miss:            {len(self.discovery_bloom_miss)}",
            f"Backoff suppressed:    {len(self.discovery_backoff)}",
            f"Deduplicated:          {len(self.discovery_dedup)}",
            f"No tree peer:          {len(self.discovery_no_tree_peer)}",
            f"Non-tree fallback:     {len(self.discovery_fallback)}",
            f"Timed out:             {len(self.discovery_timeout)}",
        ]

        if self.panics:
            lines.append("")
            lines.append("--- PANICS ---")
            for source, line in self.panics[:10]:
                lines.append(f"  [{source}] {line.strip()}")

        if self.errors:
            lines.append("")
            lines.append("--- ERRORS (first 20) ---")
            for source, line in self.errors[:20]:
                lines.append(f"  [{source}] {line.strip()}")

        if self.handshake_timeouts:
            lines.append("")
            lines.append("--- HANDSHAKE TIMEOUTS (first 10) ---")
            for source, line in self.handshake_timeouts[:10]:
                lines.append(f"  [{source}] {line.strip()}")

        lines.append("")
        return "\n".join(lines)

    @property
    def has_panics(self) -> bool:
        return len(self.panics) > 0


def analyze_text(log_text: str, source: str = "") -> AnalysisResult:
    """Analyze a single log text and return categorized events."""
    result = AnalysisResult()
    _analyze_lines(result, source, log_text)
    return result


def analyze_logs(logs: dict[str, str]) -> AnalysisResult:
    """Analyze logs from multiple sources (keyed by source name)."""
    result = AnalysisResult()
    for source, log_text in logs.items():
        _analyze_lines(result, source, log_text)
    return result


def _analyze_lines(result: AnalysisResult, source: str, log_text: str):
    """Parse log lines and append to result."""
    for raw_line in log_text.splitlines():
        line = strip_ansi(raw_line)

        # Panics
        if "panicked" in line or "PANIC" in line:
            result.panics.append((source, line))
        # Errors and warnings
        elif " ERROR " in line:
            result.errors.append((source, line))
        elif " WARN " in line:
            result.warnings.append((source, line))

        # Session establishment
        if "Session established" in line:
            result.sessions_established.append((source, line))
        # Peer promotion
        if "Inbound peer promoted" in line or "Outbound handshake completed" in line:
            result.peers_promoted.append((source, line))
        # Peer removal
        if "Peer removed" in line:
            result.peer_removals.append((source, line))
        # Parent switches
        if "Parent switched" in line:
            result.parent_switches.append((source, line))
        # Handshake timeouts
        if "timed out" in line and ("handshake" in line.lower() or "Handshake" in line):
            result.handshake_timeouts.append((source, line))
        # MMP metrics
        if "MMP link metrics" in line:
            result.mmp_link_metrics.append((source, line))
        if "MMP session metrics" in line:
            result.mmp_session_metrics.append((source, line))
        # Congestion events
        if "Congestion detected" in line:
            result.congestion_detected.append((source, line))
        if "Kernel recv drops first observed" in line:
            result.kernel_drop_events.append((source, line))
        # Rekey cutovers
        if "Rekey cutover complete" in line or "FSP rekey cutover complete" in line:
            result.rekey_cutovers.append((source, line))
        # Discovery
        if "Initiating LookupRequest" in line or "Discovery lookup initiated" in line:
            result.discovery_initiated.append((source, line))
        if "proof verified, route cached" in line:
            result.discovery_succeeded.append((source, line))
        if "target not in any peer bloom filter" in line:
            result.discovery_bloom_miss.append((source, line))
        if "suppressed by backoff" in line:
            result.discovery_backoff.append((source, line))
        if "deduplicated, already pending" in line:
            result.discovery_dedup.append((source, line))
        if "lookup timed out" in line:
            result.discovery_timeout.append((source, line))
        if "Discovery retry sent" in line:
            result.discovery_retry.append((source, line))
        if "no tree peers with bloom match" in line or "No eligible peers to forward" in line:
            result.discovery_no_tree_peer.append((source, line))
        if "non-tree fallback" in line:
            result.discovery_fallback.append((source, line))
        if "Failed to initiate session, trying discovery" in line:
            result.discovery_trigger.append((source, line))


def collect_docker_logs(containers: list[str]) -> dict[str, str]:
    """Collect logs from Docker containers, stripping ANSI codes."""
    logs = {}
    for name in containers:
        try:
            result = subprocess.run(
                ["docker", "logs", name],
                capture_output=True,
                text=True,
                timeout=30,
            )
            raw = result.stdout + result.stderr
            logs[name] = strip_ansi(raw)
        except (subprocess.TimeoutExpired, Exception):
            logs[name] = ""
    return logs


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} [--from-docker] <source> [<source> ...]",
              file=sys.stderr)
        sys.exit(1)

    from_docker = False
    args = sys.argv[1:]
    if args[0] == "--from-docker":
        from_docker = True
        args = args[1:]

    if not args:
        print("Error: no sources specified", file=sys.stderr)
        sys.exit(1)

    if from_docker:
        logs = collect_docker_logs(args)
    else:
        logs = {}
        for path in args:
            with open(path) as f:
                logs[path] = f.read()

    result = analyze_logs(logs)
    print(result.summary())
    sys.exit(2 if result.has_panics else 0)


if __name__ == "__main__":
    main()
