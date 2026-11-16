
#!/usr/bin/env python3

"""Generate irregular HTTP check-ins for BeaconScope's benign test."""

import argparse
import random
import time
import urllib.request


def send_request(url):
    request = urllib.request.Request(
        url,
        data=b"beaconscope-benign-test",
        headers={"Content-Type": "application/octet-stream"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=5) as response:
        response.read()
        return response.status


def main():
    parser = argparse.ArgumentParser(
        description="Generate irregular HTTP traffic for a local lab."
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8443/checkin",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=12,
    )
    parser.add_argument(
        "--min-delay",
        type=float,
        default=0.5,
    )
    parser.add_argument(
        "--max-delay",
        type=float,
        default=8.0,
    )
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be positive")

    if args.min_delay <= 0 or args.max_delay <= args.min_delay:
        parser.error("Delays must be positive and max-delay > min-delay")

    print(f"[benign_client] Target: {args.url}")
    print(f"[benign_client] Requests: {args.count}")

    for number in range(1, args.count + 1):
        try:
            status = send_request(args.url)
            print(f"[{number}/{args.count}] HTTP {status}")
        except Exception as error:
            print(f"[{number}/{args.count}] FAILED: {error}")

        if number < args.count:
            delay = random.uniform(
                args.min_delay,
                args.max_delay,
            )
            print(f"  Waiting {delay:.2f} seconds")
            time.sleep(delay)

    print("[benign_client] Finished")


if __name__ == "__main__":
    main()
