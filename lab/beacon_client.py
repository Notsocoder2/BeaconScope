#!/usr/bin/env python3
"""Generate labeled HTTP check-ins for an isolated BeaconScope lab.

This is a benign traffic generator, not malware. Point it only at a server you
control. ``--bind`` is useful for simulating multiple source hosts with lab IP
aliases; it does not add or configure aliases itself.
"""

import argparse
import http.client
import random
import time
from urllib.parse import urlsplit


def send_checkin(url: str, payload: bytes, bind: str | None = None, timeout: float = 5.0) -> int:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must be an absolute http:// or https:// URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(
        parsed.hostname,
        port,
        timeout=timeout,
        source_address=(bind, 0) if bind else None,
    )
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    try:
        connection.request("POST", target, body=payload,
                           headers={"Content-Type": "application/octet-stream"})
        response = connection.getresponse()
        response.read()
        if response.status >= 400:
            raise OSError(f"server returned HTTP {response.status}")
        return response.status
    finally:
        connection.close()


def run(url: str, interval: float, jitter: float, payload_bytes: int,
        count: int | None = None, duration: float | None = None,
        bind: str | None = None) -> int:
    payload = b"A" * payload_bytes
    start = time.monotonic()
    end = start + duration if duration is not None else None
    sent = attempts = 0
    print(
        f"[beacon_client] starting: interval={interval:.2f}s "
        f"jitter=+/-{jitter * 100:.0f}% target={url} "
        f"duration={duration if duration is not None else 'count=' + str(count)}"
    )
    while (time.monotonic() < end) if end is not None else (attempts < (count or 0)):
        attempts += 1
        try:
            status = send_checkin(url, payload, bind)
            sent += 1
            print(f"[{attempts}] HTTP {status} at {time.time():.3f}")
        except (OSError, ValueError, http.client.HTTPException) as exc:
            print(f"[{attempts}] check-in failed: {exc}")
        if end is not None and time.monotonic() >= end:
            break
        if count is not None and attempts >= count:
            break
        time.sleep(max(0.1, interval * (1 + random.uniform(-jitter, jitter))))
    print(f"[beacon_client] done. {sent} check-ins sent.")
    return sent


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate controlled HTTP beacon-like check-ins.")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--target", help="Destination host")
    target.add_argument("--url", help="Full check-in URL (legacy-compatible)")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--path", default="/checkin")
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--jitter", type=float, default=0.0, help="Fractional uniform interval jitter [0,1)")
    parser.add_argument("--duration", type=float, help="Run for this many seconds instead of a fixed count")
    parser.add_argument("--count", type=int, default=12, help="Check-ins in count mode (default: 12)")
    parser.add_argument("--payload-bytes", type=int, default=500)
    parser.add_argument("--bind", help="Local source IP for an existing lab alias")
    args = parser.parse_args()

    if args.interval <= 0 or args.port not in range(1, 65536):
        parser.error("--interval must be positive and --port must be in 1..65535")
    if not 0 <= args.jitter < 1:
        parser.error("--jitter must be in [0, 1)")
    if args.duration is not None and args.duration <= 0:
        parser.error("--duration must be positive")
    if args.count <= 0 or args.payload_bytes <= 0:
        parser.error("--count and --payload-bytes must be positive")
    if args.url:
        url = args.url
    else:
        url = f"http://{args.target or '127.0.0.1'}:{args.port}{args.path}"
    run(url, args.interval, args.jitter, args.payload_bytes,
        count=None if args.duration is not None else args.count,
        duration=args.duration, bind=args.bind)


if __name__ == "__main__":
    main()
