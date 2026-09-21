"""Controlled localhost server for RCScan F3 authentication and throttling demos."""

from __future__ import annotations

import argparse
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

_AUTH_HEADER = "Bearer demo-token"
_AUTH_COOKIE = "session=demo-session"


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "RCScan-F3-Synthetic/1.0"
    _lock = threading.Lock()
    _throttle_served = False

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            self._html(
                200,
                """
                <h1>RCScan F3 synthetic demo</h1>
                <a href="/protected?view=dashboard">Protected area</a>
                <a href="/throttle">Throttling route</a>
                """,
            )
            return
        if path in {"/robots.txt", "/sitemap.xml"}:
            self._text(200, "")
            return
        if path == "/protected":
            if not self._authorized():
                self._html(401, "<h1>Authentication required</h1>")
                return
            self._html(
                200,
                (
                    "<h1>Protected synthetic content</h1>"
                    '<a href="/protected/details?item=1">Protected details</a>'
                ),
            )
            return
        if path == "/protected/details":
            if not self._authorized():
                self._html(401, "<h1>Authentication required</h1>")
                return
            self._html(200, "<h1>Authorized details discovered</h1>")
            return
        if path == "/throttle":
            with self._lock:
                should_throttle = not self._throttle_served
                self._throttle_served = True
            if should_throttle:
                self.send_response(429)
                self.send_header("Retry-After", "1")
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Synthetic one-time throttle")
                return
            self._html(200, "<h1>Throttle respected; request completed</h1>")
            return
        self._html(404, "<h1>Not found</h1>")

    def _authorized(self) -> bool:
        authorization = self.headers.get("Authorization")
        cookies = {
            item.strip()
            for item in self.headers.get("Cookie", "").split(";")
            if item.strip()
        }
        return authorization == _AUTH_HEADER or _AUTH_COOKIE in cookies

    def _html(self, status: int, body: str) -> None:
        payload = (
            "<!doctype html><html><body>"
            f"{body}"
            "</body></html>"
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _text(self, status: int, body: str) -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[f3-demo] {format % args}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Serve synthetic RCScan F3 auth and throttling routes."
    )
    parser.add_argument("--port", type=int, default=8096)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DemoHandler)
    print(f"RCScan F3 synthetic demo listening on http://127.0.0.1:{args.port}")
    print("Static demo credentials: Bearer demo-token OR session=demo-session")
    print("The /throttle route returns one 429 with Retry-After: 1, then succeeds.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
