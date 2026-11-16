
#!/usr/bin/env python3

"""
BeaconScope lab: controlled HTTP check-in server.

Records check-in timestamps, client IP addresses, and payload sizes
for comparison with packet captures during later detection testing.
"""

import argparse
import http.server
from pathlib import Path
import time


def make_handler(log_path):
    class Handler(http.server.BaseHTTPRequestHandler):

        def do_POST(self):
            if self.path != "/checkin":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                self.send_error(400, "invalid Content-Length")
                return
            if not 0 <= length <= 1_048_576:
                self.send_error(413, "check-in payload must be at most 1 MiB")
                return
            payload = self.rfile.read(length)
            if len(payload) != length:
                self.send_error(400, "incomplete request body")
                return

            timestamp = time.time()

            with Path(log_path).open("a", encoding="utf-8", newline="") as log_file:
                log_file.write(
                    f"{timestamp:.3f},"
                    f"{self.client_address[0]},"
                    f"{length}\n"
                )
                log_file.flush()

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, fmt, *args):
            pass

    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--log", default="checkins.log")
    parser.add_argument("--bind", default="0.0.0.0", help="Lab listener address")
    args = parser.parse_args()
    if args.port not in range(1, 65536):
        parser.error("--port must be in 1..65535")

    with open(args.log, "w") as log_file:
        log_file.write("timestamp,client_ip,bytes\n")

    server = http.server.ThreadingHTTPServer(
        (args.bind, args.port),
        make_handler(args.log)
    )

    print(
        f"[beacon_server] listening on "
        f"{args.bind}:{args.port}, logging to {args.log}"
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[beacon_server] stopped")
    finally:
        server.server_close()
