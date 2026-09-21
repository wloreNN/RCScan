import asyncio
import json
import logging
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar

import pytest

from rcscan.active_web.engine import ActiveWebSecurityEngine
from rcscan.active_web.models import (
    ActiveWebCheckContext,
    ActiveWebCheckResult,
    ActiveWebSession,
)
from rcscan.fingerprint.models import Confidence, Service, ServiceFingerprint
from rcscan.fingerprint.probes import ProbeClient
from rcscan.network.models import (
    DiscoveryMethod,
    DiscoveryStatus,
    HostScanResult,
    PortResult,
    PortState,
)
from rcscan.web.crawler import WebCrawler
from rcscan.web.http import WebHttpClient
from rcscan.web.models import (
    ParameterSource,
    WebDiscoveryResult,
    WebEndpoint,
    WebParameter,
)
from rcscan.web.request_context import (
    AuthenticationInputError,
    WebRequestContext,
    parse_static_authentication,
)
from rcscan.web.throttle import OriginThrottleCoordinator, parse_retry_after

NOW = datetime(2026, 9, 22, tzinfo=UTC)
AUTH_SECRET = "F3_AUTH_SENTINEL_4ef287"
COOKIE_SECRET = "F3_COOKIE_SENTINEL_9a113c"


class RecordingHandler(BaseHTTPRequestHandler):
    requests: ClassVar[list[tuple[str, str | None, str | None]]] = []
    root_body = b"<html><a href='/protected?id=1'>protected</a></html>"
    redirect_to: str | None = None

    def do_HEAD(self) -> None:
        self._record()
        self.send_response(200)
        self.send_header("Server", "F3Demo/1.0")
        self.end_headers()

    def do_GET(self) -> None:
        self._record()
        if self.path == "/" and self.redirect_to is not None:
            self.send_response(302)
            self.send_header("Location", self.redirect_to)
            self.end_headers()
            return
        body = self.root_body if self.path == "/" else b"<html>protected</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Reflected-Secret", AUTH_SECRET)
        self.end_headers()
        self.wfile.write(body + AUTH_SECRET.encode())

    def _record(self) -> None:
        type(self).requests.append(
            (
                self.path,
                self.headers.get("Authorization"),
                self.headers.get("Cookie"),
            )
        )

    def log_message(self, _format: str, *args: object) -> None:
        del args


@contextmanager
def serve(handler: type[BaseHTTPRequestHandler] = RecordingHandler):
    handler.requests = []  # type: ignore[attr-defined]
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def auth_context() -> WebRequestContext:
    return WebRequestContext(
        parse_static_authentication(
            [
                f"Authorization: Bearer {AUTH_SECRET}",
                "X-Assessment: approved",
            ],
            [
                f"session={COOKIE_SECRET}",
                "csrf=static-csrf",
            ],
        )
    )


def test_auth_context_is_origin_bound_merged_and_repr_safe() -> None:
    context = auth_context()
    context.register_origin("http://site.example")
    headers = context.headers_for("http://site.example/protected")
    assert ("Authorization", f"Bearer {AUTH_SECRET}") in headers
    assert ("X-Assessment", "approved") in headers
    assert ("Cookie", f"session={COOKIE_SECRET}; csrf=static-csrf") in headers
    assert context.headers_for("http://other.example/protected") == ()
    assert AUTH_SECRET not in repr(context)
    assert COOKIE_SECRET not in repr(context)


@pytest.mark.parametrize(
    "value",
    [
        f"bad-{AUTH_SECRET}",
        f"Host: {AUTH_SECRET}",
        f"Content-Length: {AUTH_SECRET}",
        f"Transfer-Encoding: {AUTH_SECRET}",
        f"Connection: {AUTH_SECRET}",
        f"Cookie: session={AUTH_SECRET}",
    ],
)
def test_malformed_or_transport_headers_fail_without_echoing_secret(value: str) -> None:
    with pytest.raises(AuthenticationInputError) as exc_info:
        parse_static_authentication([value], None)
    assert AUTH_SECRET not in str(exc_info.value)


def test_fingerprinting_receives_static_auth_without_retaining_echoed_secret() -> None:
    context = auth_context()
    with serve() as port:
        result = asyncio.run(
            ProbeClient(
                timeout_seconds=1,
                max_banner_bytes=1_024,
                max_header_bytes=4_096,
                request_context=context,
            ).http(
                "127.0.0.1",
                port,
                method="HEAD",
                host_header=f"127.0.0.1:{port}",
                use_tls=False,
                server_hostname=None,
            )
        )
    assert RecordingHandler.requests[0][1] == f"Bearer {AUTH_SECRET}"
    assert RecordingHandler.requests[0][2] == (
        f"session={COOKIE_SECRET}; csrf=static-csrf"
    )
    assert AUTH_SECRET.encode() not in result.data


def _host(port: int) -> HostScanResult:
    now = datetime.now(UTC)
    fingerprint = ServiceFingerprint(
        service=Service.HTTP,
        confidence=Confidence.HIGH,
        evidence=(),
        probe_used="HEAD",
    )
    return HostScanResult(
        target="127.0.0.1",
        resolved_address="127.0.0.1",
        discovery_status=DiscoveryStatus.REACHABLE,
        discovery_method=DiscoveryMethod.TCP_CONNECT,
        discovery_latency_ms=1,
        ports=(
            PortResult(
                host="127.0.0.1",
                port=port,
                state=PortState.OPEN,
                latency_ms=1,
                timestamp=now,
                fingerprint=fingerprint,
            ),
        ),
        started_at=now,
        completed_at=now,
    )


def test_crawler_receives_auth_and_redacts_reflected_secrets() -> None:
    context = auth_context()
    with serve() as port:
        result = asyncio.run(
            WebCrawler(
                max_pages=4,
                max_depth=1,
                concurrency=1,
                timeout_seconds=1,
                max_response_bytes=16_384,
                max_links_per_page=20,
                request_context=context,
            ).discover((_host(port),))
        )[0]
    assert RecordingHandler.requests
    assert all(
        authorization == f"Bearer {AUTH_SECRET}"
        for _path, authorization, _cookie in RecordingHandler.requests
    )
    assert all(
        cookie == f"session={COOKIE_SECRET}; csrf=static-csrf"
        for _path, _authorization, cookie in RecordingHandler.requests
    )
    serialized = json.dumps(result.model_dump(mode="json"))
    assert AUTH_SECRET not in serialized
    assert COOKIE_SECRET not in serialized


def test_cross_origin_redirect_receives_no_credentials() -> None:
    class Destination(RecordingHandler):
        root_body = b"<html>destination</html>"

    class Redirecting(RecordingHandler):
        pass

    context = auth_context()
    with serve(Destination) as destination_port:
        Redirecting.redirect_to = f"http://127.0.0.1:{destination_port}/outside"
        with serve(Redirecting) as source_port:
            asyncio.run(
                WebCrawler(
                    max_pages=3,
                    max_depth=1,
                    concurrency=1,
                    timeout_seconds=1,
                    max_response_bytes=16_384,
                    max_links_per_page=20,
                    request_context=context,
                ).discover((_host(source_port),))
            )
    assert Destination.requests == []
    assert Redirecting.requests


def test_cross_origin_resource_is_not_requested_with_cookie() -> None:
    class Destination(RecordingHandler):
        pass

    class Source(RecordingHandler):
        pass

    context = auth_context()
    with serve(Destination) as destination_port:
        Source.root_body = (
            f"<html><img src='http://127.0.0.1:{destination_port}/asset?id=1'></html>"
        ).encode()
        with serve(Source) as source_port:
            asyncio.run(
                WebCrawler(
                    max_pages=3,
                    max_depth=1,
                    concurrency=1,
                    timeout_seconds=1,
                    max_response_bytes=16_384,
                    max_links_per_page=20,
                    request_context=context,
                ).discover((_host(source_port),))
            )
    assert Destination.requests == []


class TripleRequestCheck:
    rule_id = "f3-auth-propagation-test"

    async def evaluate(
        self,
        context: ActiveWebCheckContext,
        session: ActiveWebSession,
    ) -> ActiveWebCheckResult | None:
        await session.get(context, value_suffix="-baseline")
        await session.get(context, value_suffix="-probe")
        await session.get(context, value_suffix="-confirmation")
        return None


def test_active_web_probe_sequence_receives_auth_context() -> None:
    context = auth_context()
    with serve() as port:
        origin = f"http://127.0.0.1:{port}"
        discovery = WebDiscoveryResult(
            origin=origin,
            connect_host="127.0.0.1",
            pages_crawled=1,
            endpoints=(
                WebEndpoint(
                    url=f"{origin}/protected?id=1",
                    path="/protected",
                    depth=1,
                    status_code=200,
                    content_type="text/html",
                    body_preview="protected",
                    query_parameters=(
                        WebParameter(
                            name="id",
                            source=ParameterSource.QUERY,
                        ),
                    ),
                ),
            ),
            started_at=NOW,
            completed_at=NOW,
        )
        asyncio.run(
            ActiveWebSecurityEngine(
                timeout_seconds=1,
                max_response_bytes=16_384,
                max_requests_per_parameter=4,
                max_total_requests=4,
                concurrency=1,
                checks=(TripleRequestCheck(),),
                request_context=context,
            ).analyze((discovery,))
        )
    assert len(RecordingHandler.requests) == 3
    assert all(
        authorization == f"Bearer {AUTH_SECRET}"
        and cookie == f"session={COOKIE_SECRET}; csrf=static-csrf"
        for _path, authorization, cookie in RecordingHandler.requests
    )


class FakeWriter:
    def __init__(self) -> None:
        self.payload = b""

    def write(self, payload: bytes) -> None:
        self.payload += payload

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


def reader_with(payload: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


class FakeTime:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.value

    async def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.value += delay


def throttled_client(
    responses: list[bytes],
    fake_time: FakeTime,
    *,
    max_wait: float = 5,
    retries: int = 1,
    request_context: WebRequestContext | None = None,
) -> tuple[WebHttpClient, list[FakeWriter]]:
    writers: list[FakeWriter] = []

    async def connect(_host: str, _port: int) -> tuple[asyncio.StreamReader, Any]:
        writer = FakeWriter()
        writers.append(writer)
        return reader_with(responses[len(writers) - 1]), writer

    throttle = OriginThrottleCoordinator(
        min_request_interval_seconds=0,
        max_retry_after_seconds=max_wait,
        max_transient_retries=retries,
        sleep=fake_time.sleep,
        clock=fake_time.clock,
        wall_clock=lambda: NOW,
    )
    return (
        WebHttpClient(
            timeout_seconds=1,
            max_response_bytes=1_024,
            throttle=throttle,
            request_context=request_context,
            plain_connector=connect,
        ),
        writers,
    )


@pytest.mark.parametrize("status", [429, 503])
def test_retry_after_delay_then_success(status: int) -> None:
    fake_time = FakeTime()
    first = (
        f"HTTP/1.1 {status} Temporary\r\nRetry-After: 2\r\n"
        "Content-Type: text/plain\r\n\r\nwait"
    ).encode()
    client, writers = throttled_client(
        [first, b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"],
        fake_time,
    )
    result = asyncio.run(client.get("http://site.example/", connect_host="127.0.0.1"))
    assert result.status_code == 200
    assert len(writers) == 2
    assert fake_time.sleeps == [2.0]


def test_malformed_retry_after_uses_bounded_backoff() -> None:
    fake_time = FakeTime()
    client, writers = throttled_client(
        [
            b"HTTP/1.1 429 Busy\r\nRetry-After: nonsense\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\n",
        ],
        fake_time,
    )
    result = asyncio.run(client.get("http://site.example/", connect_host="127.0.0.1"))
    assert result.status_code == 200
    assert len(writers) == 2
    assert fake_time.sleeps == [0.25]


def test_retry_after_is_capped_and_exhaustion_is_finite() -> None:
    fake_time = FakeTime()
    busy = b"HTTP/1.1 429 Busy\r\nRetry-After: 999999\r\n\r\n"
    client, writers = throttled_client(
        [busy, busy, busy],
        fake_time,
        max_wait=1,
        retries=2,
    )
    result = asyncio.run(client.get("http://site.example/", connect_host="127.0.0.1"))
    assert result.status_code == 429
    assert len(writers) == 3
    assert fake_time.sleeps == [1.0, 1.0]


def test_temporary_transport_failure_retries_once_with_backoff() -> None:
    fake_time = FakeTime()
    calls = 0

    async def connect(_host: str, _port: int) -> tuple[asyncio.StreamReader, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("temporary synthetic failure")
        return reader_with(b"HTTP/1.1 200 OK\r\n\r\n"), FakeWriter()

    throttle = OriginThrottleCoordinator(
        min_request_interval_seconds=0,
        max_retry_after_seconds=2,
        max_transient_retries=1,
        sleep=fake_time.sleep,
        clock=fake_time.clock,
        wall_clock=lambda: NOW,
    )
    result = asyncio.run(
        WebHttpClient(
            timeout_seconds=1,
            max_response_bytes=1_024,
            throttle=throttle,
            plain_connector=connect,
        ).get("http://site.example/", connect_host="127.0.0.1")
    )
    assert result.status_code == 200
    assert calls == 2
    assert fake_time.sleeps == [0.25]


def test_retry_reserver_prevents_request_budget_amplification() -> None:
    fake_time = FakeTime()
    client, writers = throttled_client(
        [
            b"HTTP/1.1 429 Busy\r\nRetry-After: 1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\n",
        ],
        fake_time,
    )

    async def deny_retry() -> bool:
        return False

    result = asyncio.run(
        client.get(
            "http://site.example/",
            connect_host="127.0.0.1",
            retry_reserver=deny_retry,
        )
    )
    assert result.status_code == 429
    assert len(writers) == 1
    assert fake_time.sleeps == []


def test_verbose_throttling_diagnostic_never_contains_auth_secret() -> None:
    fake_time = FakeTime()
    context = auth_context()
    context.register_origin("http://site.example")
    client, writers = throttled_client(
        [
            b"HTTP/1.1 429 Busy\r\nRetry-After: 1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\n",
        ],
        fake_time,
        request_context=context,
    )
    records: list[str] = []

    class RecordHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record.getMessage())

    logger = logging.getLogger("rcscan.web.throttle")
    previous_level = logger.level
    previous_propagate = logger.propagate
    handler = RecordHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    try:
        asyncio.run(client.get("http://site.example/", connect_host="127.0.0.1"))
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate
    diagnostics = "\n".join(records)
    assert b"Authorization: Bearer " + AUTH_SECRET.encode() in writers[0].payload
    assert "HTTP throttling detected" in diagnostics
    assert AUTH_SECRET not in diagnostics
    assert COOKIE_SECRET not in diagnostics


def test_retry_after_http_date_and_malformed_values() -> None:
    value = format_datetime(NOW + timedelta(seconds=3), usegmt=True)
    assert parse_retry_after(value, now=NOW) == 3
    assert parse_retry_after("not-a-date", now=NOW) is None


def test_workers_share_origin_backoff_and_cancellation_propagates() -> None:
    async def scenario() -> None:
        release = asyncio.Event()
        calls = 0

        async def blocking_sleep(_delay: float) -> None:
            nonlocal calls
            calls += 1
            await release.wait()

        coordinator = OriginThrottleCoordinator(
            min_request_interval_seconds=0,
            max_retry_after_seconds=2,
            max_transient_retries=1,
            sleep=blocking_sleep,
        )
        await coordinator.backoff(
            "http://site.example/",
            status_code=429,
            retry_after="1",
            retry_number=1,
        )
        tasks = [
            asyncio.create_task(coordinator.wait("http://site.example/a")),
            asyncio.create_task(coordinator.wait("http://site.example/b")),
        ]
        await asyncio.sleep(0)
        assert calls == 2
        tasks[0].cancel()
        with pytest.raises(asyncio.CancelledError):
            await tasks[0]
        release.set()
        await tasks[1]

    asyncio.run(scenario())
