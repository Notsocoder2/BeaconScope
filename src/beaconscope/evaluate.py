"""Reproducible labeled evaluation for scored BeaconScope channels."""

from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path
from typing import Any, Iterable, Mapping

from .features import extract_features
from .scoring import score_channel
from .simulate import (
    destination_for_channel,
    labeled_dataset,
    synthetic_topology,
)
from .suppress import check_suppression, load_baseline


def _score(record: Mapping[str, Any]) -> float:
    return float(record.get("score", record.get("beacon_score", "nan")))


def _average_precision(labels: list[int], scores: list[float]) -> float:
    positives = sum(labels)
    if not labels or positives == 0:
        return float("nan")
    order = sorted(range(len(scores)), key=lambda index: scores[index], reverse=True)
    tp = fp = 0
    previous_recall = 0.0
    area = 0.0
    cursor = 0
    while cursor < len(order):
        threshold_score = scores[order[cursor]]
        while cursor < len(order) and scores[order[cursor]] == threshold_score:
            if labels[order[cursor]]:
                tp += 1
            else:
                fp += 1
            cursor += 1
        recall = tp / positives
        precision = tp / (tp + fp)
        area += (recall - previous_recall) * precision
        previous_recall = recall
    return area


def confusion_metrics(records: Iterable[Mapping[str, Any]], threshold: float) -> dict[str, Any]:
    """Compute threshold metrics and step-wise PR-AUC from labeled rows."""
    if not 0.0 <= threshold <= 1.0 or not math.isfinite(threshold):
        raise ValueError("threshold must be finite and between 0 and 1")
    labeled = [row for row in records if row.get("label") in (0, 1, "0", "1")]
    labels = [int(row["label"]) for row in labeled]
    scores = [_score(row) for row in labeled]
    if any(not math.isfinite(value) or not 0 <= value <= 1 for value in scores):
        raise ValueError("scores must be finite and between 0 and 1")

    tp = fp = tn = fn = 0
    effective_scores = []
    for row, label, score in zip(labeled, labels, scores):
        suppressed = str(row.get("suppressed", "false")).lower() in ("true", "1", "yes")
        timing_supported = str(row.get("timing_supported", "true")).lower() not in ("false", "0", "no")
        effective_scores.append(0.0 if suppressed or not timing_supported else score)
        predicted = score >= threshold and not suppressed and timing_supported
        if label and predicted:
            tp += 1
        elif label:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else float("nan")
    recall = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if tp and precision + recall else float("nan")
    negatives = tn + fp
    return {
        "total_labeled": len(labeled),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fp / negatives if negatives else float("nan"),
        "true_positive_rate": recall,
        "pr_auc_average_precision": _average_precision(labels, effective_scores),
        "raw_pr_auc_average_precision": _average_precision(labels, scores),
        "threshold": threshold,
    }


def run_synthetic_evaluation(
    threshold: float = 0.5,
    seed: int = 42,
    suppress: bool = False,
    fanin_threshold: int = 3,
    allowlist: Iterable[str] = (),
    weights: Mapping[str, float] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    """Run the fixed-seed synthetic set and return rows, metrics, jitter table."""
    data = labeled_dataset(seed)
    channel_ids = [channel_id for channel_id, *_ in data]
    topology = synthetic_topology(channel_ids)
    rows: list[dict[str, Any]] = []
    for channel_id, timestamps, sizes, label in data:
        features = extract_features(timestamps, sizes)
        scored = score_channel(features, weights)
        destination = destination_for_channel(channel_id)
        source = next(
            host for host, destinations in topology.items() if destination in destinations
        )
        suppression = check_suppression(
            destination, topology, allowlist, fanin_threshold
        ) if suppress else None
        rows.append({
            "channel": channel_id,
            "src_ip": source,
            "destination": destination,
            "label": label,
            "score": scored.score,
            "timing_supported": scored.timing_supported,
            "raw_predicted": int(scored.is_alert(threshold)),
            "suppressed": bool(suppression and suppression.suppressed),
            "suppression_reason": suppression.reason if suppression else "",
            "predicted": int(
                scored.is_alert(threshold) and not (suppression and suppression.suppressed)
            ),
            "explanation": scored.explanation,
            **features.as_dict(),
        })

    final_metrics = confusion_metrics(rows, threshold)
    raw_rows = [dict(row, suppressed=False) for row in rows]
    raw_metrics = confusion_metrics(raw_rows, threshold)
    metrics = dict(final_metrics)
    metrics.update({
        f"raw_{key}": value
        for key, value in raw_metrics.items()
        if key not in ("threshold", "raw_pr_auc_average_precision")
    })

    jitter_rows: list[dict[str, Any]] = []
    for jitter in (0.0, 0.1, 0.2, 0.3, 0.5):
        subset = [row for row in rows if row["channel"].startswith("beacon_") and f"_j{jitter}" in row["channel"]]
        values = confusion_metrics(subset, threshold)
        jitter_rows.append({"jitter_fraction": jitter, **values})
    return rows, metrics, jitter_rows


def load_results(results_path: str | Path) -> list[dict[str, Any]]:
    path = Path(results_path)
    if not path.is_file():
        raise FileNotFoundError(f"input file not found: {path}")
    with path.open("r", newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise ValueError("input CSV is empty")
        records = list(reader)
    return records


def load_labels(labels_path: str | Path) -> tuple[dict[tuple[str, ...], int], bool]:
    """Load labels keyed by full channel identity when provided."""
    path = Path(labels_path)
    with path.open("r", newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        required = {"dst_ip", "dst_port", "label"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError("labels CSV needs dst_ip,dst_port,label columns")
        use_source = "src_ip" in reader.fieldnames
        use_protocol = "protocol" in reader.fieldnames
        labels: dict[tuple[str, ...], int] = {}
        for line, row in enumerate(reader, start=2):
            try:
                label = int(row["label"])
                port = int(row["dst_port"])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid label or port on labels CSV row {line}") from exc
            if label not in (0, 1) or not 0 <= port <= 65535:
                raise ValueError(f"invalid label or port on labels CSV row {line}")
            key: tuple[str, ...] = (row["dst_ip"].strip(), str(port))
            if use_source:
                key += (row["src_ip"].strip(),)
            if use_protocol:
                key += (row["protocol"].strip().lower(),)
            if key in labels:
                raise ValueError(f"duplicate label key on labels CSV row {line}: {key}")
            labels[key] = label
    return labels, use_source or use_protocol


def match_label(record: Mapping[str, Any], labels: Mapping[tuple[str, ...], int], strict: bool) -> int | None:
    destination = str(record.get("dst_ip", record.get("destination", ""))).strip()
    try:
        port = str(int(record.get("dst_port", 0)))
    except (TypeError, ValueError):
        port = "0"
    protocol = str(record.get("protocol", "")).lower()
    source = str(record.get("src_ip", "")).strip()
    candidates = [(destination, port, source, protocol), (destination, port, source),
                  (destination, port, protocol), (destination, port)]
    for key in candidates:
        if key in labels:
            return labels[key]
    return None


def evaluate_with_labels(
    records: list[Mapping[str, Any]],
    labels: Mapping[tuple[str, ...], int],
    use_protocol: bool,
    threshold: float,
) -> dict[str, Any]:
    """Compatibility helper for callers that already loaded label mappings."""
    rows = []
    unlabeled = 0
    for record in records:
        label = match_label(record, labels, use_protocol)
        if label is None:
            unlabeled += 1
            continue
        rows.append({**record, "label": label, "score": _score(record)})
    result = confusion_metrics(rows, threshold)
    result["unlabeled_groups"] = unlabeled
    result["precision"] = round(result["precision"], 4) if math.isfinite(result["precision"]) else result["precision"]
    result["recall"] = round(result["recall"], 4) if math.isfinite(result["recall"]) else result["recall"]
    result["f1_score"] = round(result["f1_score"], 4) if math.isfinite(result["f1_score"]) else result["f1_score"]
    return result


def _records_from_scored(records: list[dict[str, Any]], threshold: float, suppress: bool,
                         fanin_threshold: int, allowlist: Iterable[str]) -> list[dict[str, Any]]:
    topology: dict[str, set[str]] = {}
    for record in records:
        if record.get("src_ip") and record.get("dst_ip"):
            topology.setdefault(record["src_ip"], set()).add(record["dst_ip"])
    output = []
    for record in records:
        try:
            score = _score(record)
        except (TypeError, ValueError) as exc:
            raise ValueError("scored input needs a numeric score or beacon_score") from exc
        label = record.get("label")
        if label not in (0, 1, "0", "1"):
            continue
        suppression = check_suppression(
            record.get("dst_ip", ""), topology, allowlist, fanin_threshold
        ) if suppress else None
        output.append({
            **record,
            "score": score,
            "label": int(label),
            "suppressed": bool(suppression and suppression.suppressed),
            "suppression_reason": suppression.reason if suppression else "",
        })
    return output


def _write_csv(path: Path, rows: list[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("\n", encoding="utf-8")
        return
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate BeaconScope against labeled channels.")
    parser.add_argument("--input", help="Scored channels CSV")
    parser.add_argument("--labels", help="CSV labels; can also be embedded in input rows")
    parser.add_argument("--output", default="evaluation_summary.csv", help="Summary CSV output")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--synthetic", action="store_true", help="Run fixed-seed synthetic evaluation")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--suppress", action="store_true", help="Enable destination rarity suppression")
    parser.add_argument("--baseline", help="Benign baseline CSV with a destination column")
    parser.add_argument("--fanin-threshold", type=int, default=3)
    args = parser.parse_args()
    if not 0 <= args.threshold <= 1:
        parser.error("--threshold must be between 0 and 1")
    if args.fanin_threshold < 1:
        parser.error("--fanin-threshold must be at least 1")
    if args.synthetic and (args.input or args.labels):
        parser.error("--synthetic cannot be combined with --input or --labels")
    if not args.synthetic and not args.input:
        parser.error("provide --input or --synthetic")
    try:
        if args.synthetic:
            allowlist = load_baseline(args.baseline) if args.baseline else set()
            rows, summary, jitter_rows = run_synthetic_evaluation(
                args.threshold, args.seed, args.suppress, args.fanin_threshold, allowlist
            )
            summary["suppression_enabled"] = args.suppress
            output_path = Path(args.output)
            _write_csv(output_path.with_name(output_path.stem + "_channels.csv"), rows)
            _write_csv(output_path.with_name(output_path.stem + "_jitter.csv"), jitter_rows)
        else:
            rows = load_results(args.input)
            labels, strict = load_labels(args.labels) if args.labels else ({}, False)
            labeled = []
            unlabeled = 0
            for row in rows:
                label = int(row["label"]) if row.get("label") in ("0", "1", 0, 1) else (
                    match_label(row, labels, strict) if labels else None
                )
                if label is None:
                    unlabeled += 1
                else:
                    labeled.append({**row, "label": label, "score": _score(row)})
            allowlist = load_baseline(args.baseline) if args.baseline else set()
            labeled = _records_from_scored(labeled, args.threshold, args.suppress,
                                            args.fanin_threshold, allowlist)
            summary = confusion_metrics(labeled, args.threshold)
            summary["unlabeled_groups"] = unlabeled
            summary["suppression_enabled"] = args.suppress
            output_path = Path(args.output)
            _write_csv(output_path.with_name(output_path.stem + "_channels.csv"), labeled)
        _write_csv(output_path, [summary])
    except (FileNotFoundError, ValueError, KeyError) as exc:
        parser.error(str(exc))

    print("BeaconScope evaluation")
    for key, value in summary.items():
        print(f"{key}: {value}")
    if args.synthetic:
        print("Jitter recall:")
        for row in jitter_rows:
            print(f"  {row['jitter_fraction']:.0%}: {row['recall']}")


if __name__ == "__main__":
    main()
