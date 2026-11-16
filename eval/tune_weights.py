"""Compare a small, explicit weight set on the seeded synthetic corpus.

This is a teaching aid, not an optimizer for production thresholds. The
reported corpus is also used for the sweep, so these metrics must not be
presented as held-out performance. Defaults in scoring.py are not changed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from beaconscope.evaluate import run_synthetic_evaluation
from beaconscope.scoring import DEFAULT_WEIGHTS


CANDIDATES = {
    "default": DEFAULT_WEIGHTS,
    "timing_focused": {
        "jitter_tolerant_regularity": 0.40,
        "spectral_score": 0.40,
        "size_regularity": 0.05,
        "persistence_score": 0.05,
        "min_connections_bonus": 0.10,
    },
    "without_size_signal": {
        "jitter_tolerant_regularity": 0.35,
        "spectral_score": 0.35,
        "size_regularity": 0.0,
        "persistence_score": 0.20,
        "min_connections_bonus": 0.10,
    },
    "balanced_context": {
        "jitter_tolerant_regularity": 0.25,
        "spectral_score": 0.25,
        "size_regularity": 0.20,
        "persistence_score": 0.20,
        "min_connections_bonus": 0.10,
    },
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()
    results = []
    for name, weights in CANDIDATES.items():
        _, metrics, _ = run_synthetic_evaluation(
            threshold=args.threshold, seed=args.seed, suppress=False, weights=weights
        )
        results.append({
            "candidate": name,
            "weights": weights,
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1_score": metrics["f1_score"],
            "false_positives": metrics["false_positives"],
            "false_negatives": metrics["false_negatives"],
        })
    print(json.dumps({
        "warning": "Exploratory training-set comparison only; do not treat as held-out performance.",
        "seed": args.seed,
        "threshold": args.threshold,
        "results": results,
    }, indent=2))


if __name__ == "__main__":
    main()
