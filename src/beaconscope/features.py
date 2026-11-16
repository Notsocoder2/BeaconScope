"""Statistical features for one observed network channel.

The measurements describe beacon-like behavior, not malicious intent. The
functions accept event timestamps and optional per-event outbound byte counts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from typing import Iterable

import numpy as np


@dataclass(frozen=True)
class ChannelFeatures:
    n_connections: int
    duration_s: float
    median_interval: float
    interval_mad: float
    jitter_tolerant_regularity: float
    spectral_score: float
    size_regularity: float
    persistence_score: float

    def as_dict(self) -> dict[str, int | float]:
        return asdict(self)


def _as_finite_array(values: Iterable[float], name: str) -> np.ndarray:
    try:
        result = np.asarray(list(values), dtype=float)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must contain numeric values") from exc
    if result.ndim != 1 or not np.isfinite(result).all():
        raise ValueError(f"{name} must be a one-dimensional finite sequence")
    return result


def _intervals(timestamps: np.ndarray) -> np.ndarray:
    return np.diff(np.sort(timestamps))


def jitter_tolerant_regularity(intervals: Iterable[float], tol_frac: float = 0.3) -> float:
    """Return the fraction of intervals within 30% of their median.

    A robust timing signal for bounded random jitter. Fewer than three
    observations (two intervals) are not enough to claim regularity.
    """
    values = _as_finite_array(intervals, "intervals")
    if not math.isfinite(tol_frac) or tol_frac < 0:
        raise ValueError("tol_frac must be a finite non-negative value")
    if len(values) < 2:
        return 0.0
    median = float(np.median(values))
    if median <= 0:
        return 0.0
    return float(np.mean(np.abs(values - median) <= tol_frac * median))


def spectral_score(
    timestamps: Iterable[float], bin_seconds: float = 1.0, max_bins: int = 20_000
) -> float:
    """Measure the strongest non-trivial autocorrelation peak via FFT.

    Events are binned into a count series. The bin width grows for long
    observation windows so memory remains bounded. This is a heuristic score,
    not a significance test; broad peaks may still occur in benign traffic.
    """
    ts = np.sort(_as_finite_array(timestamps, "timestamps"))
    if not math.isfinite(bin_seconds) or bin_seconds <= 0:
        raise ValueError("bin_seconds must be positive and finite")
    if max_bins < 8:
        raise ValueError("max_bins must be at least 8")
    if len(ts) < 4:
        return 0.0
    span = float(ts[-1] - ts[0])
    if span < bin_seconds * 4:
        return 0.0

    width = max(bin_seconds, span / (max_bins - 1))
    n_bins = min(max_bins, int(span / width) + 1)
    indices = ((ts - ts[0]) / width).astype(int)
    indices = indices[(indices >= 0) & (indices < n_bins)]
    series = np.bincount(indices, minlength=n_bins).astype(float)
    series -= series.mean()
    if np.allclose(series, 0.0):
        return 0.0

    fft_size = 1 << (2 * len(series) - 1).bit_length()
    spectrum = np.fft.rfft(series, n=fft_size)
    autocorrelation = np.fft.irfft(spectrum * np.conjugate(spectrum), n=fft_size)[: len(series)]
    if autocorrelation[0] <= 0:
        return 0.0
    autocorrelation /= autocorrelation[0]

    min_lag = max(2, int(math.ceil(2.0 / width)))
    max_lag = max(min_lag, len(autocorrelation) // 2)
    if min_lag >= max_lag:
        return 0.0
    peak = float(np.max(autocorrelation[min_lag:max_lag + 1]))
    return float(np.clip(peak, 0.0, 1.0))


def size_regularity(sizes: Iterable[float]) -> float:
    """Return clipped ``1 - CV`` across positive outbound event sizes."""
    values = _as_finite_array(sizes, "sizes")
    values = values[values > 0]
    if len(values) < 2:
        return 0.0
    average = float(np.mean(values))
    if average <= 0:
        return 0.0
    cv = float(np.std(values) / average)
    return float(np.clip(1.0 - cv, 0.0, 1.0))


def persistence_score(timestamps: Iterable[float], n_bins: int = 10) -> float:
    """Fraction of equal-width bins in the capture window containing events."""
    ts = np.sort(_as_finite_array(timestamps, "timestamps"))
    if n_bins < 1:
        raise ValueError("n_bins must be positive")
    if len(ts) < 2 or ts[-1] <= ts[0]:
        return 0.0
    edges = np.linspace(ts[0], ts[-1], n_bins + 1)
    counts, _ = np.histogram(ts, bins=edges)
    return float(np.mean(counts > 0))


def extract_features(
    timestamps: Iterable[float], sizes: Iterable[float] | None = None
) -> ChannelFeatures:
    """Calculate timing, periodicity, size, and persistence features."""
    ts = np.sort(_as_finite_array(timestamps, "timestamps"))
    size_values = np.asarray([], dtype=float) if sizes is None else _as_finite_array(sizes, "sizes")
    if sizes is not None and len(size_values) not in (0, len(ts)):
        raise ValueError("sizes must be empty or have one entry per timestamp")

    intervals = _intervals(ts)
    interval_median = float(np.median(intervals)) if len(intervals) else 0.0
    interval_mad = (
        float(np.median(np.abs(intervals - interval_median))) if len(intervals) else 0.0
    )
    return ChannelFeatures(
        n_connections=len(ts),
        duration_s=float(ts[-1] - ts[0]) if len(ts) > 1 else 0.0,
        median_interval=interval_median,
        interval_mad=interval_mad,
        jitter_tolerant_regularity=jitter_tolerant_regularity(intervals),
        spectral_score=spectral_score(ts),
        size_regularity=size_regularity(size_values),
        persistence_score=persistence_score(ts),
    )
