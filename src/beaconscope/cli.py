"""Offline BeaconScope PCAP analysis pipeline."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any

from .evaluate import confusion_metrics, load_labels, match_label
from .features import extract_features
from .pcap_to_channels import (
    extract_channels,
    extract_dns_features,
    write_channels,
    write_dns_features,
)
from .scoring import score_channel
from .suppress import check_suppression, load_baseline


def _write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("\n", encoding="utf-8")
        return
    fieldnames = list(dict.fromkeys(field for row in rows for field in row))
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def run_pipeline(
    pcap_path: Path,
    output_dir: Path,
    threshold: float = 0.5,
    suppress: bool = False,
    baseline_path: Path | None = None,
    fanin_threshold: int = 3,
    internal_networks: list[str] | None = None,
    labels_path: Path | None = None,
) -> dict[str, Any]:
    """Extract, score, contextualize, and export one PCAP analysis."""
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be between 0 and 1")
    if fanin_threshold < 1:
        raise ValueError("fanin_threshold must be at least 1")
    pcap_path = pcap_path.resolve()
    output_dir = output_dir.resolve()
    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
    output_dir.mkdir(parents=True, exist_ok=True)

    channels = extract_channels(pcap_path, internal_networks)
    write_channels(channels, output_dir / "channels.csv")
    dns_rows = extract_dns_features(pcap_path, internal_networks)
    write_dns_features(dns_rows, output_dir / "dns_features.csv")
    topology: dict[str, set[str]] = {}
    for channel in channels.values():
        topology.setdefault(channel.src, set()).add(channel.dst)
    allowlist = load_baseline(str(baseline_path)) if baseline_path else set()

    feature_rows: list[dict[str, Any]] = []
    scored_rows: list[dict[str, Any]] = []
    for channel in sorted(channels.values(), key=lambda item: item.channel_id):
        features = extract_features(channel.timestamps, channel.sizes)
        scored = score_channel(features)
        suppression = check_suppression(
            channel.dst, topology, allowlist, fanin_threshold
        ) if suppress else None
        suppressed = bool(suppression and suppression.suppressed)
        feature_rows.append({
            "channel_id": channel.channel_id,
            "src_ip": channel.src,
            "dst_ip": channel.dst,
            "dst_port": channel.port,
            "protocol": channel.proto,
            **features.as_dict(),
        })
        scored_rows.append({
            "channel_id": channel.channel_id,
            "src_ip": channel.src,
            "dst_ip": channel.dst,
            "dst_port": channel.port,
            "protocol": channel.proto,
            "score": scored.score,
            "threshold": threshold,
            "timing_supported": scored.timing_supported,
            "alert": int(scored.is_alert(threshold) and not suppressed),
            "suppressed": suppressed,
            "suppression_reason": suppression.reason if suppression else "",
            "explanation": scored.explanation,
            **features.as_dict(),
        })
    _write_rows(output_dir / "features.csv", feature_rows)

    summary: dict[str, Any] = {
        "total_channels": len(scored_rows),
        "dns_domains": len(dns_rows),
        "alerts": sum(row["alert"] for row in scored_rows),
        "suppressed_channels": sum(row["suppressed"] for row in scored_rows),
        "threshold": threshold,
        "suppression_enabled": suppress,
        "labeled_channels": 0,
    }
    if labels_path:
        labels, strict = load_labels(labels_path)
        labeled_rows = []
        for row in scored_rows:
            label = match_label(row, labels, strict)
            if label is not None:
                labeled_rows.append({**row, "label": label})
        metrics = confusion_metrics(labeled_rows, threshold)
        summary.update(metrics)
        summary["labeled_channels"] = len(labeled_rows)
        summary["unlabeled_channels"] = len(scored_rows) - len(labeled_rows)
        _write_rows(output_dir / "labeled_scored_connections.csv", labeled_rows)

    _write_rows(output_dir / "scored_connections.csv", scored_rows)
    _write_rows(output_dir / "evaluation_summary.csv", [summary])
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze a PCAP for beacon-like channels.")
    parser.add_argument("--pcap", required=True, help="Input PCAP or PCAPNG file")
    parser.add_argument("--output-dir", default="eval/results/beaconscope_run")
    parser.add_argument("--threshold", type=float, default=0.5, help="Heuristic score threshold (0-1)")
    parser.add_argument("--suppress", action="store_true", help="Enable benign baseline and destination fan-in suppression")
    parser.add_argument("--baseline", help="Benign baseline CSV with a destination column")
    parser.add_argument("--fanin-threshold", type=int, default=3)
    parser.add_argument("--internal-cidr", action="append", dest="internal_networks", help="Internal source network; repeat as needed")
    parser.add_argument("--labels", help="Optional labels CSV for actual evaluation metrics")
    args = parser.parse_args()
    try:
        summary = run_pipeline(
            Path(args.pcap), Path(args.output_dir), args.threshold, args.suppress,
            Path(args.baseline) if args.baseline else None, args.fanin_threshold,
            args.internal_networks, Path(args.labels) if args.labels else None,
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        parser.error(str(exc))
    print("BeaconScope channel ranking")
    scored_path = Path(args.output_dir).resolve() / "scored_connections.csv"
    with scored_path.open("r", newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    for row in sorted(rows, key=lambda item: float(item["score"]), reverse=True):
        status = "SUPPRESSED" if row["suppressed"] == "True" else (
            "ALERT" if row["alert"] == "1" else "INFO"
        )
        print(
            f"[{status}] {row['src_ip']} -> {row['dst_ip']}:{row['dst_port']}/"
            f"{row['protocol']} score={float(row['score']):.3f} "
            f"{row['explanation']}"
        )
    print(f"Summary: {summary}")
    print(f"Outputs: {scored_path.parent}")


if __name__ == "__main__":
    main()
