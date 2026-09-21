"""Bounded passive, HTTP, and TLS fingerprint probes."""

from __future__ import annotations

import asyncio
import ssl as ssl_module
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from time import perf_counter
from typing import Any, Protocol, cast

from rcscan import __version__
from rcscan.fingerprint.evidence import safe_preview
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


class SSLObjectLike(Protocol):
    def version(self) -> str | None: ...

    def cipher(self) -> tuple[str, str, int] | None: ...

    def getpeercert(self) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class ReadProbeResult:
    data: bytes
    latency_ms: float
    truncated: bool = False
    error: str | None = None


@dataclass(frozen=True, slots=True)
class TLSProbeResult:
    succeeded: bool
    latency_ms: float
    version: str | None = None
    cipher: str | None = None
    certificate: dict[str, str] | None = None
    error: str | None = None


class ProbeClient:
    """Perform small probes with strict time and byte limits."""

    def __init__(
        self,
        *,
        timeout_seconds: float,
        max_banner_bytes: int,
        max_header_bytes: int,
        request_context: WebRequestContext | None = None,
        throttle: OriginThrottleCoordinator | None = None,
        plain_connector: PlainConnect | None = None,
        tls_connector: TLSConnect | None = None,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._max_banner_bytes = max_banner_bytes
        self._max_header_bytes = max_header_bytes
        self._request_context = request_context or WebRequestContext()
        self._throttle = throttle
        self._plain_connector = plain_connector or _open_plain
        self._tls_connector = tls_connector or _open_tls

    async def passive_banner(self, host: str, port: int) -> ReadProbeResult:
        started = perf_counter()
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(self._timeout_seconds):
                reader, writer = await self._plain_connector(host, port)
                data = await reader.read(self._max_banner_bytes + 1)
            return ReadProbeResult(
                data=data[: self._max_banner_bytes],
                truncated=len(data) > self._max_banner_bytes,
                latency_ms=(perf_counter() - started) * 1_000,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return ReadProbeResult(
                data=b"",
                latency_ms=(perf_counter() - started) * 1_000,
                error=_safe_error(exc),
            )
        finally:
            if writer is not None:
                await _close_writer(writer)

    async def http(
        self,
        host: str,
        port: int,
        *,
        method: str,
        host_header: str,
        use_tls: bool,
        server_hostname: str | None,
    ) -> ReadProbeResult:
        started = perf_counter()
        writer: asyncio.StreamWriter | None = None
        scheme = "https" if use_tls else "http"
        origin = f"{scheme}://{host_header}"
        self._request_context.register_origin(origin)
        try:
            if self._throttle is not None:
                await self._throttle.wait(origin)
            async with asyncio.timeout(self._timeout_seconds):
                if use_tls:
                    reader, writer = await self._tls_connector(
                        host,
                        port,
                        ssl=create_inspection_context(),
                        server_hostname=server_hostname,
                        ssl_handshake_timeout=self._timeout_seconds,
                    )
                else:
                    reader, writer = await self._plain_connector(host, port)
                request = _http_request(
                    method,
                    host_header,
                    self._request_context.headers_for(origin),
                )
                writer.write(request)
                await writer.drain()
                data, truncated = await _read_http_headers(
                    reader,
                    self._max_header_bytes,
                )
            return ReadProbeResult(
                data=self._request_context.redact_bytes(data),
                truncated=truncated,
                latency_ms=(perf_counter() - started) * 1_000,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return ReadProbeResult(
                data=b"",
                latency_ms=(perf_counter() - started) * 1_000,
                error=self._request_context.redact_text(_safe_error(exc)),
            )
        finally:
            if writer is not None:
                await _close_writer(writer)

    async def tls(
        self,
        host: str,
        port: int,
        *,
        server_hostname: str | None,
    ) -> TLSProbeResult:
        started = perf_counter()
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(self._timeout_seconds):
                _, writer = await self._tls_connector(
                    host,
                    port,
                    ssl=create_inspection_context(),
                    server_hostname=server_hostname,
                    ssl_handshake_timeout=self._timeout_seconds,
                )
            ssl_object = cast(SSLObjectLike | None, writer.get_extra_info("ssl_object"))
            if ssl_object is None:
                return TLSProbeResult(
                    succeeded=False,
                    latency_ms=(perf_counter() - started) * 1_000,
                    error="TLS connection completed without TLS session metadata.",
                )
            cipher = ssl_object.cipher()
            return TLSProbeResult(
                succeeded=True,
                latency_ms=(perf_counter() - started) * 1_000,
                version=ssl_object.version(),
                cipher=cipher[0] if cipher else None,
                certificate=_certificate_metadata(ssl_object.getpeercert()),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return TLSProbeResult(
                succeeded=False,
                latency_ms=(perf_counter() - started) * 1_000,
                error=_safe_error(exc),
            )
        finally:
            if writer is not None:
                await _close_writer(writer)


def create_inspection_context() -> ssl_module.SSLContext:
    """Create an isolated context for identification of authorized endpoints."""
    context = ssl_module.create_default_context(ssl_module.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl_module.CERT_NONE
    return context


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
        # asyncio substitutes ``host`` when this is None. An empty value
        # explicitly suppresses SNI for raw IP targets.
        server_hostname=server_hostname or "",
        ssl_handshake_timeout=ssl_handshake_timeout,
    )


def _http_request(
    method: str,
    host_header: str,
    additional_headers: tuple[tuple[str, str], ...] = (),
) -> bytes:
    safe_host = host_header.replace("\r", "").replace("\n", "")[:253]
    request = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {safe_host}\r\n"
        f"User-Agent: RCScan/{__version__}\r\n"
        "Connection: close\r\n"
    ).encode("ascii")
    custom = b"".join(
        f"{name}: {value}\r\n".encode("latin-1")
        for name, value in additional_headers
    )
    return request + custom + b"\r\n"


async def _read_http_headers(
    reader: asyncio.StreamReader,
    limit: int,
) -> tuple[bytes, bool]:
    buffer = bytearray()
    while len(buffer) <= limit:
        remaining = limit + 1 - len(buffer)
        chunk = await reader.read(min(1_024, remaining))
        if not chunk:
            break
        buffer.extend(chunk)
        for delimiter in (b"\r\n\r\n", b"\n\n"):
            position = buffer.find(delimiter)
            if position >= 0:
                end = position + len(delimiter)
                return bytes(buffer[:end]), False
    return bytes(buffer[:limit]), len(buffer) > limit


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


def _certificate_metadata(certificate: dict[str, Any]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for key in ("serialNumber", "notBefore", "notAfter"):
        value = certificate.get(key)
        if value:
            metadata[key] = str(value)[:256]
    for key in ("subject", "issuer", "subjectAltName"):
        value = certificate.get(key)
        if value:
            metadata[key] = _safe_metadata_value(value)
    return metadata


def _safe_metadata_value(value: object) -> str:
    return safe_preview(str(value).encode("utf-8"), limit=512)


def _safe_error(exc: BaseException) -> str:
    message = " ".join(str(exc).split())[:200]
    return f"{exc.__class__.__name__}: {message}" if message else exc.__class__.__name__
