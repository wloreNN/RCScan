"""Localhost-only synthetic site demonstrating passive M8A findings."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "127.0.0.1"
DEFAULT_PORT = 8083


class DemoSecurityHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "DemoServer/1.2.3"

    def do_HEAD(self) -> None:
        self._respond(include_body=False)

    def do_GET(self) -> None:
        self._respond(include_body=True)

    def _respond(self, *, include_body: bool) -> None:
        pages = {
            "/": (
                "text/html",
                b"""
                <h1>Synthetic M8A demo</h1>
                <a href="/debug">Synthetic debug page</a>
                <a href="/backup.bak">Synthetic backup artifact</a>
                """,
            ),
            "/debug": (
                "text/html",
                b"""
                <h1>Synthetic development error</h1>
                Traceback (most recent call last):
                File "C:\\Users\\demo\\synthetic.py", line 1
                ValueError: synthetic demo exception
                """,
            ),
            "/backup.bak": (
                "text/plain",
                b"SYNTHETIC BACKUP MARKER - NO REAL SECRET",
            ),
            "/robots.txt": (
                "text/plain",
                b"User-agent: *\nDisallow: /private-admin\n",
            ),
            "/sitemap.xml": (
                "application/xml",
                b"<urlset><url><loc>/debug</loc></url></urlset>",
            ),
        }
        entry = pages.get(self.path)
        if entry is None:
            self.send_error(404)
            return
        content_type, body = entry
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Set-Cookie",
            "sessionid=SYNTHETIC-NOT-A-SECRET; Path=/",
        )
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Connection", "close")
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        message = (format % args).encode("ascii", errors="backslashreplace").decode()
        print(f"{self.client_address[0]} - {message}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the synthetic M8A demo site.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    if not 1 <= args.port <= 65_535:
        parser.error("--port must be between 1 and 65535.")
    server = HTTPServer((HOST, args.port), DemoSecurityHandler)
    print(f"Synthetic M8A demo listening only on http://{HOST}:{args.port}/")
    print("All issues and data are synthetic. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSynthetic M8A demo stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
