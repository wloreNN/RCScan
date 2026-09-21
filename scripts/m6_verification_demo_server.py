"""Localhost-only synthetic server for M6 active-verification acceptance."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "127.0.0.1"
DEFAULT_PORT = 8081
PATH = "/rcscan-demo-status"
BODY = b"RCSCAN_M6_DEMO_OK\n"


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "RCScanDemo/1.0.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def do_HEAD(self) -> None:
        self._respond(include_body=False)

    def do_GET(self) -> None:
        self._respond(include_body=True)

    def _respond(self, *, include_body: bool) -> None:
        if self.path != PATH:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        if include_body:
            self.wfile.write(BODY)

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.client_address[0]} - {format % args}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the localhost-only synthetic RCScan M6 demo server."
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    if not 1 <= args.port <= 65_535:
        parser.error("--port must be between 1 and 65535.")
    return args


def main() -> None:
    args = parse_args()
    server = HTTPServer((HOST, args.port), DemoHandler)
    print("RCScan M6 SYNTHETIC localhost verification server")
    print("This is NOT a real vulnerable service and performs no outbound traffic.")
    print(f"Listening only on http://{HOST}:{args.port}{PATH}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSynthetic M6 demo server stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
