"""Explainable weighted scoring for observed BeaconScope channels."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Mapping

from .features import ChannelFeatures


DEFAULT_WEIGHTS: dict[str, float] = {
    "jitter_tolerant_regularity": 0.30,
    "spectral_score": 0.30,
    "size_regularity": 0.15,
    "persistence_score": 0.15,
    "min_connections_bonus": 0.10,
}
MIN_CONNECTIONS_FOR_CONFIDENCE = 6


@dataclass(frozen=True)
class ScoredChannel:
    score: float
    explanation: str
    features: ChannelFeatures
    timing_supported: bool

    def is_alert(self, threshold: float = 0.5) -> bool:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1")
        return self.score >= threshold and self.timing_supported


def _validated_weights(weights: Mapping[str, float] | None) -> dict[str, float]:
    values = dict(DEFAULT_WEIGHTS if weights is None else weights)
    if set(values) != set(DEFAULT_WEIGHTS):
        raise ValueError(f"weights must contain exactly: {', '.join(DEFAULT_WEIGHTS)}")
    if any(not math.isfinite(float(value)) or float(value) < 0 for value in values.values()):
        raise ValueError("weights must be finite and non-negative")
    if not math.isclose(sum(map(float, values.values())), 1.0, abs_tol=1e-9):
        raise ValueError("weights must sum to 1.0")
    return {name: float(value) for name, value in values.items()}


def score_channel(
    features: ChannelFeatures, weights: Mapping[str, float] | None = None
) -> ScoredChannel:
    """Return a 0–1 heuristic score and feature-based explanation.

    The observation-count contribution is a confidence adjustment, not a
    maliciousness signal. Scores are deliberately not described as
    probabilities.
    """
    weights = _validated_weights(weights)
    feature_values = (
        features.jitter_tolerant_regularity,
        features.spectral_score,
        features.size_regularity,
        features.persistence_score,
    )
    if features.n_connections < 0 or any(
        not math.isfinite(value) or not 0.0 <= value <= 1.0
        for value in feature_values
    ):
        raise ValueError("feature values must be finite and within [0, 1]")

    confidence = min(1.0, features.n_connections / MIN_CONNECTIONS_FOR_CONFIDENCE)
    timing_supported = (
        features.jitter_tolerant_regularity >= 0.5 or features.spectral_score >= 0.4
    )
    components = {
        "jitter_tolerant_regularity": features.jitter_tolerant_regularity,
        "spectral_score": features.spectral_score,
        "size_regularity": features.size_regularity,
        "persistence_score": features.persistence_score,
        "min_connections_bonus": confidence,
    }
    score = sum(weights[name] * components[name] for name in weights)
    score = float(min(1.0, max(0.0, score)))

    reasons: list[str] = []
    if features.jitter_tolerant_regularity > 0.6:
        reasons.append(
            f"{features.jitter_tolerant_regularity:.0%} of intervals cluster near "
            f"{features.median_interval:.1f}s"
        )
    if features.spectral_score > 0.4:
        reasons.append(f"autocorrelation peak {features.spectral_score:.2f}")
    if features.size_regularity > 0.6:
        reasons.append("outbound request sizes are unusually uniform")
    if features.persistence_score > 0.6:
        reasons.append("activity persists across the observation window")
    if features.n_connections < MIN_CONNECTIONS_FOR_CONFIDENCE:
        reasons.append(f"low confidence: only {features.n_connections} events observed")
    if not timing_supported:
        reasons.append("no timing corroboration; size and persistence alone do not meet the beacon gate")
    if not reasons:
        reasons.append("no strong periodicity signal")
    return ScoredChannel(score, "; ".join(reasons), features, timing_supported)
