"""Synthetic localhost behavior for controlled M8B active checks."""

from __future__ import annotations

import argparse
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

HOST = "127.0.0.1"
DEFAULT_PORT = 8084
SYNTHETIC_UNIX_MARKER = b"""\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www:/var/www:/usr/sbin/nologin
"""
SYNTHETIC_WINDOWS_MARKER = b"""\
; synthetic Windows initialization marker
[fonts]
[extensions]
[mci extensions]
"""


class ActiveDemoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    scenario = "all"

    def version_string(self) -> str:
        path = urlsplit(self.path).path
        if path == "/windows-download":
            return "Microsoft-IIS/10.0"
        if path == "/download":
            return "nginx/1.24.0"
        return "SyntheticM8B/1.0"

    def do_HEAD(self) -> None:
        self._respond(include_body=False)

    def do_GET(self) -> None:
        self._respond(include_body=True)

    def _respond(self, *, include_body: bool) -> None:
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        status = 200
        content_type = "text/html; charset=utf-8"
        if parsed.path == "/":
            links = {
                "unix": (
                    '<a href="/download?file=manual.pdf">'
                    "Synthetic Unix traversal</a>"
                ),
                "windows": (
                    '<a href="/windows-download?file=manual.ini">'
                    "Synthetic Windows traversal</a>"
                ),
                "safe": (
                    '<a href="/safe-download?file=manual.pdf">'
                    "Safe traversal comparison</a>"
                ),
            }
            selected = (
                tuple(links.values())
                if self.scenario == "all"
                else (links[self.scenario],)
            )
            extras = (
                (
                    '<a href="/encoded-download?file=manual.txt">'
                    "Synthetic encoded traversal</a>",
                    '<a href="/product?id=1">Synthetic SQL differential</a>',
                    '<a href="/filter?category=Gifts">'
                    "Synthetic boolean SQL differential</a>",
                    '<a href="/search?q=hello">Synthetic raw reflection</a>',
                )
                if self.scenario == "all"
                else ()
            )
            body = (
                "<h1>Synthetic M8B demo</h1>\n"
                + "\n".join((*selected, *extras))
            ).encode()
        elif parsed.path == "/product":
            value = query.get("id", [""])[0]
            if value.endswith("'"):
                status = 500
                body = b"SQLSTATE[42000] SYNTHETIC parser error; no database exists"
            else:
                body = f"<p>Synthetic product {html.escape(value)}</p>".encode()
        elif parsed.path == "/safe-product":
            value = query.get("id", [""])[0]
            body = f"<p>Safely handled {html.escape(value)}</p>".encode()
        elif parsed.path == "/filter":
            value = query.get("category", [""])[0]
            body = (
                b"<ul><li>No matching synthetic products</li></ul>"
                if "'1'='2" in value
                else b"<ul><li>Alpha</li><li>Beta</li><li>Gamma</li></ul>"
            )
        elif parsed.path == "/safe-filter":
            body = b"<ul><li>Stable safely handled catalog</li></ul>"
        elif parsed.path == "/search":
            value = query.get("q", [""])[0]
            body = f"<p>Synthetic search: {value}</p>".encode()
        elif parsed.path == "/safe-search":
            value = query.get("q", [""])[0]
            body = f"<p>Encoded search: {html.escape(value)}</p>".encode()
        elif parsed.path == "/download":
            value = query.get("file", [""])[0]
            body = (
                SYNTHETIC_UNIX_MARKER
                if "../" in value and value.endswith("etc/passwd")
                else b"<p>Synthetic requested document</p>"
            )
        elif parsed.path == "/windows-download":
            value = query.get("file", [""])[0].casefold()
            body = (
                SYNTHETIC_WINDOWS_MARKER
                if "..\\" in value and value.endswith("windows\\win.ini")
                else b"<p>Synthetic requested Windows document</p>"
            )
        elif parsed.path == "/encoded-download":
            value = query.get("file", [""])[0]
            encoded_traversal = "%2e%2e" in parsed.query.casefold()
            if "../" in value and value.endswith("etc/passwd") and encoded_traversal:
                body = SYNTHETIC_UNIX_MARKER
            elif "../" in value or "..\\" in value:
                status = 404
                body = b"<p>Synthetic canonical traversal rejected</p>"
            else:
                body = b"<p>Synthetic requested encoded document</p>"
        elif parsed.path == "/safe-download":
            value = query.get("file", [""])[0]
            body = (
                f"<p>Allowlisted synthetic file lookup rejected: "
                f"{html.escape(value)}</p>"
            ).encode()
        elif parsed.path == "/robots.txt":
            content_type = "text/plain"
            body = b"User-agent: *\nAllow: /\n"
        elif parsed.path == "/sitemap.xml":
            content_type = "application/xml"
            body = b"<urlset></urlset>"
        else:
            self.send_error(404)
            return
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Connection", "close")
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        message = (format % args).encode("ascii", errors="backslashreplace").decode()
        print(f"{self.client_address[0]} - {message}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the synthetic M8B demo.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--scenario",
        choices=("all", "unix", "windows", "safe"),
        default="all",
        help="Expose all demonstrations or one traversal acceptance case.",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65_535:
        parser.error("--port must be between 1 and 65535.")
    ActiveDemoHandler.scenario = args.scenario
    server = HTTPServer((HOST, args.port), ActiveDemoHandler)
    print(f"Synthetic M8B demo listening only on http://{HOST}:{args.port}/")
    print(f"Scenario: {args.scenario}")
    print("No database, filesystem reads, JavaScript execution, or exploitation exists.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSynthetic M8B demo stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
