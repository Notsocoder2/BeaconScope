"""Deterministic synthetic channels for offline evaluation and regression tests."""

from __future__ import annotations

import numpy as np


def _generator(rng: np.random.Generator | None) -> np.random.Generator:
    return np.random.default_rng() if rng is None else rng


def _validate(duration_s: float, interval_s: float) -> None:
    if not np.isfinite(duration_s) or duration_s <= 0:
        raise ValueError("duration_s must be positive and finite")
    if not np.isfinite(interval_s) or interval_s <= 0:
        raise ValueError("interval_s must be positive and finite")


def make_beacon(
    duration_s: float,
    interval_s: float,
    jitter_frac: float,
    size_mean: float = 500,
    size_jitter_frac: float = 0.05,
    rng: np.random.Generator | None = None,
) -> tuple[list[float], list[float]]:
    """Generate a beacon with uniform interval and payload-size jitter."""
    _validate(duration_s, interval_s)
    if not np.isfinite(jitter_frac) or not 0 <= jitter_frac < 1:
        raise ValueError("jitter_frac must be in [0, 1)")
    if not np.isfinite(size_mean) or size_mean <= 0:
        raise ValueError("size_mean must be positive and finite")
    if not np.isfinite(size_jitter_frac) or not 0 <= size_jitter_frac < 1:
        raise ValueError("size_jitter_frac must be in [0, 1)")
    generator = _generator(rng)
    count = max(1, int(duration_s / interval_s))
    intervals = interval_s * (1 + generator.uniform(-jitter_frac, jitter_frac, size=count))
    timestamps = np.cumsum(intervals)
    sizes = size_mean * (1 + generator.uniform(-size_jitter_frac, size_jitter_frac, size=count))
    return timestamps.tolist(), sizes.tolist()


def make_benign_periodic(
    duration_s: float, interval_s: float, rng: np.random.Generator | None = None
) -> tuple[list[float], list[float]]:
    """Generate periodic update/NTP-like traffic with loss and variable sizes."""
    _validate(duration_s, interval_s)
    generator = _generator(rng)
    count = max(1, int(duration_s / interval_s))
    intervals = interval_s * (1 + generator.uniform(-0.05, 0.05, size=count))
    timestamps = np.cumsum(intervals)
    keep = generator.random(count) > 0.1
    timestamps = timestamps[keep]
    sizes = generator.uniform(200, 4000, size=len(timestamps))
    return timestamps.tolist(), sizes.tolist()


def make_random_browsing(
    duration_s: float, rate_per_hour: float, rng: np.random.Generator | None = None
) -> tuple[list[float], list[float]]:
    """Generate sparse, irregular web activity."""
    if not np.isfinite(rate_per_hour) or rate_per_hour < 0:
        raise ValueError("rate_per_hour must be finite and non-negative")
    _validate(duration_s, 1.0)
    generator = _generator(rng)
    count = int(duration_s / 3600 * rate_per_hour)
    timestamps = np.sort(generator.uniform(0, duration_s, size=count))
    sizes = generator.lognormal(mean=8, sigma=1.5, size=count)
    return timestamps.tolist(), sizes.tolist()


def labeled_dataset(seed: int = 42) -> list[tuple[str, list[float], list[float], int]]:
    """Return seeded six-hour beacon and benign channels with binary labels."""
    rng = np.random.default_rng(seed)
    data: list[tuple[str, list[float], list[float], int]] = []
    duration = 6 * 3600
    for jitter in (0.0, 0.1, 0.2, 0.3, 0.5):
        for interval in (30, 60, 300):
            timestamps, sizes = make_beacon(duration, interval, jitter, rng=rng)
            data.append((f"beacon_i{interval}_j{jitter}", timestamps, sizes, 1))
    for interval in (60, 300, 900):
        timestamps, sizes = make_benign_periodic(duration, interval, rng=rng)
        data.append((f"benign_periodic_{interval}", timestamps, sizes, 0))
    for rate in (5, 20, 100):
        timestamps, sizes = make_random_browsing(duration, rate, rng=rng)
        data.append((f"benign_browsing_{rate}", timestamps, sizes, 0))
    return data


def synthetic_topology(channel_ids: list[str]) -> dict[str, set[str]]:
    """Create an explicit multi-host fan-in scenario for suppression testing.

    Beacon destinations are unique to one source. Each periodic benign service
    is contacted by four source hosts. This topology is simulated ground truth,
    not information inferred from the channel timing series.
    """
    topology: dict[str, set[str]] = {}
    for index, channel_id in enumerate(channel_ids, start=10):
        source = f"10.0.0.{index}"
        if channel_id.startswith("benign_periodic_"):
            destination = "shared-service:" + channel_id.rsplit("_", 1)[-1]
            topology.setdefault(source, set()).add(destination)
            for alias in range(1, 4):
                topology.setdefault(f"10.0.{index}.{alias}", set()).add(destination)
        else:
            destination = "unique:" + channel_id
            topology.setdefault(source, set()).add(destination)
    return topology


def destination_for_channel(channel_id: str) -> str:
    if channel_id.startswith("benign_periodic_"):
        return "shared-service:" + channel_id.rsplit("_", 1)[-1]
    return "unique:" + channel_id
