"""Localhost-only synthetic site for M7 web-discovery acceptance."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "127.0.0.1"
DEFAULT_PORT = 8082


class DemoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_HEAD(self) -> None:
        self._respond(include_body=False)

    def do_GET(self) -> None:
        self._respond(include_body=True)

    def _respond(self, *, include_body: bool) -> None:
        pages = {
            "/": (
                "text/html; charset=utf-8",
                b"""
                <html><head>
                  <script src="/static/app.js"></script>
                  <link rel="stylesheet" href="/static/app.css">
                </head><body>
                  <a href="/about">About</a>
                  <a href="/items?page=1">Items</a>
                  <a href="https://outside.invalid/must-not-follow">External</a>
                  <form method="get" action="/search">
                    <input name="q" type="search">
                  </form>
                  <form method="post" action="/login">
                    <input name="user"><input name="password" type="password">
                  </form>
                  <script>const api = "/api/v1/status";</script>
                </body></html>
                """,
            ),
            "/about": ("text/html", b'<a href="/">Home</a>'),
            "/items?page=1": ("text/html", b"<p>Page one</p>"),
            "/api/v1/status": ("text/plain", b'{"status":"demo"}'),
            "/robots.txt": (
                "text/plain",
                b"User-agent: *\nDisallow: /private\nAllow: /\nSitemap: /sitemap.xml\n",
            ),
            "/sitemap.xml": (
                "application/xml",
                b"<urlset><url><loc>/from-sitemap</loc></url></urlset>",
            ),
            "/from-sitemap": ("text/html", b"<p>Mapped page</p>"),
            "/static/app.js": ("application/javascript", b"// not executed\n"),
            "/static/app.css": ("text/css", b"body { color: #222; }\n"),
        }
        entry = pages.get(self.path)
        if entry is None:
            self.send_error(404)
            return
        content_type, body = entry
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        message = (format % args).encode("ascii", errors="backslashreplace").decode()
        print(f"{self.client_address[0]} - {message}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the localhost M7 demo site.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    if not 1 <= args.port <= 65_535:
        parser.error("--port must be between 1 and 65535.")
    server = HTTPServer((HOST, args.port), DemoHandler)
    print(f"M7 demo site listening only on http://{HOST}:{args.port}/")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nM7 demo site stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
