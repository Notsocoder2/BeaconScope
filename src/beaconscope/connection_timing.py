"""Compatibility utility exporting channel interval summaries from PCAPs."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
import statistics

from .pcap_to_channels import extract_channels


FIELDS = [
    "src_ip", "dst_ip", "dst_port", "protocol", "connection_count",
    "interval_count", "interval_mean", "interval_median", "interval_std", "interval_cv",
]


def analyze_periodicity(pcap_path: str | Path, internal_networks: list[str] | None = None) -> list[dict[str, object]]:
    """Calculate per-channel intervals from TCP starts and UDP first datagrams."""
    channels = extract_channels(pcap_path, internal_networks)
    results = []
    for channel in channels.values():
        intervals = [later - earlier for earlier, later in zip(channel.timestamps, channel.timestamps[1:])]
        average = statistics.mean(intervals) if intervals else 0.0
        std = statistics.pstdev(intervals) if len(intervals) >= 2 else 0.0
        cv = std / average if average > 0 else 0.0
        results.append({
            "src_ip": channel.src,
            "dst_ip": channel.dst,
            "dst_port": channel.port,
            "protocol": channel.proto,
            "connection_count": len(channel.timestamps),
            "interval_count": len(intervals),
            "interval_mean": average,
            "interval_median": statistics.median(intervals) if intervals else 0.0,
            "interval_std": std,
            "interval_cv": cv,
        })
    return sorted(results, key=lambda row: (str(row["src_ip"]), str(row["dst_ip"]), int(row["dst_port"]), str(row["protocol"])))


def main() -> None:
    parser = argparse.ArgumentParser(description="Export channel interval statistics.")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--internal-cidr", action="append", dest="internal_networks")
    args = parser.parse_args()
    try:
        rows = analyze_periodicity(args.pcap, args.internal_networks)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[BeaconScope] Connection groups: {len(rows)}")
    print(f"[BeaconScope] Results saved to: {output}")


if __name__ == "__main__":
    main()
