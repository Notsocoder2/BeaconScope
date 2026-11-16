"""Contextual suppression for baseline-known and high-fan-in destinations.

Suppression changes the alert decision, not the underlying feature score. The
reason is retained so analysts can review and override contextual suppression.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


@dataclass(frozen=True)
class SuppressionResult:
    suppressed: bool
    reason: str | None


def destination_fanin(destination: str, host_to_destinations: Mapping[str, Iterable[str]]) -> int:
    """Count distinct source hosts that contacted ``destination``."""
    return sum(1 for destinations in host_to_destinations.values() if destination in destinations)


def check_suppression(
    destination: str,
    host_to_destinations: Mapping[str, Iterable[str]],
    allowlist: Iterable[str] = (),
    fanin_threshold: int = 3,
) -> SuppressionResult:
    """Check a learned benign allowlist, then multi-host destination fan-in."""
    if fanin_threshold < 1:
        raise ValueError("fanin_threshold must be at least 1")
    known_benign = set(allowlist)
    if destination in known_benign:
        return SuppressionResult(True, f"{destination} is in the benign baseline allowlist")
    fanin = destination_fanin(destination, host_to_destinations)
    if fanin >= fanin_threshold:
        return SuppressionResult(
            True,
            f"{fanin} distinct source hosts contacted {destination} (fan-in threshold {fanin_threshold})",
        )
    return SuppressionResult(False, None)


def build_allowlist_from_baseline(
    baseline_channels: Iterable[tuple[str, str]],
) -> set[str]:
    """Learn destination keys from a separate, benign-only baseline capture."""
    return {destination for _source, destination in baseline_channels}


def load_baseline(path: str) -> set[str]:
    """Read an allowlist CSV with a required ``destination`` column."""
    import csv
    from pathlib import Path

    baseline_path = Path(path)
    if not baseline_path.is_file():
        raise FileNotFoundError(f"baseline CSV not found: {baseline_path}")
    with baseline_path.open("r", newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or "destination" not in reader.fieldnames:
            raise ValueError("baseline CSV must contain a 'destination' column")
        return {row["destination"].strip() for row in reader if row.get("destination", "").strip()}
