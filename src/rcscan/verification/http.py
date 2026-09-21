"""Dedicated bounded HTTP transport for reviewed verification rules."""

from __future__ import annotations

import asyncio
import re
import ssl as ssl_module
from collections.abc import Awaitable, Callable
from contextlib import suppress
from ipaddress import ip_address
from time import perf_counter
from typing import Protocol

from rcscan import __version__
from rcscan.findings.models import Finding
from rcscan.fingerprint.models import Service
from rcscan.verification.models import HttpExchange, VerificationRule
from rcscan.web.request_context import WebRequestContext
from rcscan.web.throttle import OriginThrottleCoordinator

PlainConnect = Callable[
    [str, int],
    Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]


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


class VerificationHttpClient:
    def __init__(
        self,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        request_context: WebRequestContext | None = None,
        throttle: OriginThrottleCoordinator | None = None,
        plain_connector: PlainConnect | None = None,
        tls_connector: TLSConnect | None = None,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._request_context = request_context or WebRequestContext()
        self._throttle = throttle
        self._plain_connector = plain_connector or _open_plain
        self._tls_connector = tls_connector or _open_tls

    async def request(
        self,
        finding: Finding,
        rule: VerificationRule,
    ) -> HttpExchange:
        started = perf_counter()
        writer: asyncio.StreamWriter | None = None
        timeout = min(self._timeout_seconds, rule.timeout_seconds)
        scheme = "https" if finding.service is Service.HTTPS else "http"
        default_port = 443 if scheme == "https" else 80
        authority = (
            finding.host
            if finding.port == default_port
            else f"{finding.host}:{finding.port}"
        )
        origin = f"{scheme}://{authority}"
        self._request_context.register_origin(origin)
        try:
            if self._throttle is not None:
                await self._throttle.wait(origin)
            async with asyncio.timeout(timeout):
                if finding.service is Service.HTTPS:
                    reader, writer = await self._tls_connector(
                        finding.host,
                        finding.port,
                        ssl=_inspection_context(),
                        server_hostname=_server_hostname(finding.host),
                        ssl_handshake_timeout=timeout,
                    )
                else:
                    reader, writer = await self._plain_connector(
                        finding.host,
                        finding.port,
                    )
                writer.write(
                    _build_request(
                        finding.host,
                        rule,
                        self._request_context.headers_for(origin),
                    )
                )
                await writer.drain()
                payload, truncated = await _read_bounded(
                    reader,
                    self._max_response_bytes,
                )
            if truncated:
                return HttpExchange(
                    body=payload,
                    truncated=True,
                    duration_ms=(perf_counter() - started) * 1_000,
                )
            payload = self._request_context.redact_bytes(payload)
            return _parse_response(payload, (perf_counter() - started) * 1_000)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return HttpExchange(
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
    host: str,
    rule: VerificationRule,
    additional_headers: tuple[tuple[str, str], ...] = (),
) -> bytes:
    safe_host = host.replace("\r", "").replace("\n", "")[:253]
    request = (
        f"{rule.method.value} {rule.path} HTTP/1.1\r\n"
        f"Host: {safe_host}\r\n"
        f"User-Agent: RCScan/{__version__} active-verification\r\n"
        "Accept: text/plain\r\n"
        "Connection: close\r\n"
    ).encode("ascii")
    custom = b"".join(
        f"{name}: {value}\r\n".encode("latin-1")
        for name, value in additional_headers
    )
    return request + custom + b"\r\n"


async def _read_bounded(
    reader: asyncio.StreamReader,
    limit: int,
) -> tuple[bytes, bool]:
    payload = bytearray()
    while len(payload) <= limit:
        remaining = limit + 1 - len(payload)
        chunk = await reader.read(min(1_024, remaining))
        if not chunk:
            break
        payload.extend(chunk)
    return bytes(payload[:limit]), len(payload) > limit


def _parse_response(payload: bytes, duration_ms: float) -> HttpExchange:
    match = re.search(rb"\r?\n\r?\n", payload)
    if match is None:
        return HttpExchange(malformed=True, duration_ms=duration_ms)
    header_block = payload[: match.start()]
    body = payload[match.end() :]
    lines = header_block.splitlines()
    if not lines:
        return HttpExchange(malformed=True, duration_ms=duration_ms)
    status = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: .*)?", lines[0])
    if status is None:
        return HttpExchange(malformed=True, duration_ms=duration_ms)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            return HttpExchange(malformed=True, duration_ms=duration_ms)
        name, value = line.split(b":", 1)
        try:
            normalized_name = name.decode("ascii").strip().lower()
            normalized_value = value.decode("latin-1").strip()
        except UnicodeDecodeError:
            return HttpExchange(malformed=True, duration_ms=duration_ms)
        if not normalized_name:
            return HttpExchange(malformed=True, duration_ms=duration_ms)
        headers.setdefault(normalized_name[:100], normalized_value[:500])
    return HttpExchange(
        status_code=int(status.group(1)),
        headers=headers,
        body=body,
        duration_ms=duration_ms,
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
