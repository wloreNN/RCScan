"""Cancellation-safe bounded HTTP transport for web discovery."""

from __future__ import annotations

import asyncio
import ssl as ssl_module
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field
from ipaddress import ip_address
from time import perf_counter
from typing import Protocol
from urllib.parse import urlsplit

from rcscan import __version__
from rcscan.web.models import WebCookie
from rcscan.web.request_context import WebRequestContext
from rcscan.web.throttle import OriginThrottleCoordinator

PlainConnect = Callable[
    [str, int],
    Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]
RetryReserver = Callable[[], Awaitable[bool]]


class TLSConnect(Protocol):
    def __call__(
        self,
        host: str,
        port: int,
        *,
        ssl: ssl_module.SSLContext,
        server_hostname: str | None,
        ssl_handshake_timeout: float,
    ) -> Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]: ...


@dataclass(frozen=True)
class WebResponse:
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: tuple[WebCookie, ...] = ()
    body: bytes = b""
    bytes_received: int = 0
    truncated: bool = False
    malformed: bool = False
    error: str | None = None
    duration_ms: float = 0


class WebHttpClient:
    def __init__(
        self,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        retain_body_for_all_content_types: bool = False,
        request_context: WebRequestContext | None = None,
        throttle: OriginThrottleCoordinator | None = None,
        plain_connector: PlainConnect | None = None,
        tls_connector: TLSConnect | None = None,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._retain_body_for_all_content_types = (
            retain_body_for_all_content_types
        )
        self._request_context = request_context or WebRequestContext()
        self._throttle = throttle
        self._plain_connector = plain_connector or _open_plain
        self._tls_connector = tls_connector or _open_tls

    def register_origin(self, origin: str) -> None:
        self._request_context.register_origin(origin)

    async def get(
        self,
        url: str,
        *,
        connect_host: str,
        retry_reserver: RetryReserver | None = None,
    ) -> WebResponse:
        retry_number = 0
        while True:
            if self._throttle is not None:
                await self._throttle.wait(url)
            response = await self._get_once(url, connect_host=connect_host)
            retry_after = response.headers.get("retry-after")
            retryable_status = response.status_code == 429 or (
                response.status_code == 503 and retry_after is not None
            )
            retryable_failure = response.error is not None
            if not retryable_status and not retryable_failure:
                if self._throttle is not None:
                    self._throttle.note_success(url)
                return response
            if (
                self._throttle is None
                or retry_number >= self._throttle.max_transient_retries
            ):
                return response
            if retry_reserver is not None and not await retry_reserver():
                return response
            retry_number += 1
            await self._throttle.backoff(
                url,
                status_code=response.status_code,
                retry_after=retry_after,
                retry_number=retry_number,
            )

    async def _get_once(self, url: str, *, connect_host: str) -> WebResponse:
        started = perf_counter()
        writer: asyncio.StreamWriter | None = None
        try:
            parsed = urlsplit(url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            async with asyncio.timeout(self._timeout_seconds):
                if parsed.scheme == "https":
                    reader, writer = await self._tls_connector(
                        connect_host,
                        port,
                        ssl=_inspection_context(),
                        server_hostname=_server_hostname(parsed.hostname or ""),
                        ssl_handshake_timeout=self._timeout_seconds,
                    )
                else:
                    reader, writer = await self._plain_connector(connect_host, port)
                writer.write(
                    _build_request(
                        url,
                        self._request_context.headers_for(url),
                    )
                )
                await writer.drain()
                header_payload, initial_body, header_error = await _read_headers(reader)
                if header_error is not None:
                    return WebResponse(
                        malformed=True,
                        error=header_error,
                        duration_ms=(perf_counter() - started) * 1_000,
                    )
                status, headers, cookies = _parse_headers(header_payload)
                headers = {
                    name: self._request_context.redact_text(value)
                    for name, value in headers.items()
                }
                if status is None:
                    return WebResponse(
                        malformed=True,
                        duration_ms=(perf_counter() - started) * 1_000,
                    )
                content_type = headers.get("content-type", "").casefold()
                if (
                    not self._retain_body_for_all_content_types
                    and not _is_parseable_content(content_type)
                ):
                    return WebResponse(
                        status_code=status,
                        headers=headers,
                        cookies=cookies,
                        bytes_received=len(initial_body),
                        duration_ms=(perf_counter() - started) * 1_000,
                    )
                body, truncated, bytes_received = await _read_body_bounded(
                    reader,
                    initial_body,
                    self._max_response_bytes,
                )
                body = self._request_context.redact_bytes(body)
            return WebResponse(
                status_code=status,
                headers=headers,
                cookies=cookies,
                body=body,
                bytes_received=bytes_received,
                truncated=truncated,
                duration_ms=(perf_counter() - started) * 1_000,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return WebResponse(
                error=self._request_context.redact_text(_safe_error(exc)),
                duration_ms=(perf_counter() - started) * 1_000,
            )
        finally:
            if writer is not None:
                await _close_writer(writer)


async def _open_plain(
    host: str,
    port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection(host, port)


async def _open_tls(
    host: str,
    port: int,
    *,
    ssl: ssl_module.SSLContext,
    server_hostname: str | None,
    ssl_handshake_timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection(
        host,
        port,
        ssl=ssl,
        server_hostname=server_hostname or "",
        ssl_handshake_timeout=ssl_handshake_timeout,
    )


def _inspection_context() -> ssl_module.SSLContext:
    context = ssl_module.create_default_context(ssl_module.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl_module.CERT_NONE
    return context


def _server_hostname(host: str) -> str | None:
    try:
        ip_address(host)
    except ValueError:
        return host
    return None


def _build_request(
    url: str,
    additional_headers: tuple[tuple[str, str], ...] = (),
) -> bytes:
    parsed = urlsplit(url)
    target = parsed.path or "/"
    if parsed.query:
        target += f"?{parsed.query}"
    host = parsed.hostname or ""
    default_port = 443 if parsed.scheme == "https" else 80
    if parsed.port is not None and parsed.port != default_port:
        host = f"{host}:{parsed.port}"
    request = (
        f"GET {target} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: RCScan/{__version__} web-discovery\r\n"
        "Accept: text/html, application/xhtml+xml, application/xml, text/xml, text/plain\r\n"
        "Connection: close\r\n"
    ).encode("ascii")
    custom = b"".join(
        f"{name}: {value}\r\n".encode("latin-1")
        for name, value in additional_headers
    )
    return request + custom + b"\r\n"


async def _read_headers(
    reader: asyncio.StreamReader,
) -> tuple[bytes, bytes, str | None]:
    payload = bytearray()
    while len(payload) <= 16_384:
        chunk = await reader.read(1)
        if not chunk:
            return b"", b"", "Connection closed before HTTP headers completed."
        payload.extend(chunk)
        for delimiter in (b"\r\n\r\n", b"\n\n"):
            position = payload.find(delimiter)
            if position >= 0:
                body_start = position + len(delimiter)
                return bytes(payload[:position]), bytes(payload[body_start:]), None
    return b"", b"", "HTTP headers exceeded 16384 bytes."


def _parse_headers(
    payload: bytes,
) -> tuple[int | None, dict[str, str], tuple[WebCookie, ...]]:
    lines = payload.splitlines()
    if not lines:
        return None, {}, ()
    parts = lines[0].split(b" ", 2)
    if (
        len(parts) < 2
        or parts[0] not in {b"HTTP/1.0", b"HTTP/1.1"}
        or len(parts[1]) != 3
        or not parts[1].isdigit()
    ):
        return None, {}, ()
    status = int(parts[1])
    if not 100 <= status <= 599:
        return None, {}, ()
    headers: dict[str, str] = {}
    cookies: list[WebCookie] = []
    for line in lines[1:]:
        if b":" not in line:
            return None, {}, ()
        raw_name, raw_value = line.split(b":", 1)
        try:
            name = raw_name.decode("ascii").strip().casefold()
            value = raw_value.decode("latin-1").strip()
        except UnicodeDecodeError:
            return None, {}, ()
        if not name:
            return None, {}, ()
        if name == "set-cookie":
            cookie = _parse_cookie_metadata(value)
            if cookie is not None and len(cookies) < 50:
                cookies.append(cookie)
        else:
            headers.setdefault(name[:100], value[:500])
    return status, headers, tuple(cookies)


def _parse_cookie_metadata(value: str) -> WebCookie | None:
    parts = [part.strip() for part in value.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()[:100]
    if not name or any(character.isspace() for character in name):
        return None
    attributes = {part.casefold() for part in parts[1:]}
    same_site = next(
        (
            part.split("=", 1)[1].strip()[:20]
            for part in parts[1:]
            if part.casefold().startswith("samesite=")
        ),
        None,
    )
    return WebCookie(
        name=name,
        secure="secure" in attributes,
        http_only="httponly" in attributes,
        same_site=same_site,
    )


def _is_parseable_content(content_type: str) -> bool:
    media_type = content_type.split(";", 1)[0].strip()
    return (
        not media_type
        or media_type.startswith("text/")
        or media_type in {
            "application/xhtml+xml",
            "application/xml",
            "application/sitemap+xml",
        }
        or media_type.endswith("+xml")
    )


async def _read_body_bounded(
    reader: asyncio.StreamReader,
    initial: bytes,
    limit: int,
) -> tuple[bytes, bool, int]:
    payload = bytearray(initial[:limit])
    bytes_received = len(payload)
    while len(payload) < limit:
        chunk = await reader.read(min(8_192, limit - len(payload)))
        if not chunk:
            break
        bytes_received += len(chunk)
        payload.extend(chunk)
    return (
        bytes(payload),
        len(initial) > limit or len(payload) == limit,
        bytes_received,
    )


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    close_task = asyncio.ensure_future(writer.wait_closed())
    try:
        await asyncio.shield(close_task)
    except asyncio.CancelledError:
        with suppress(ConnectionError, OSError):
            await close_task
        raise
    except (ConnectionError, OSError):
        pass


def _safe_error(exc: BaseException) -> str:
    message = " ".join(str(exc).split())[:240]
    return f"{exc.__class__.__name__}: {message}" if message else exc.__class__.__name__
