import asyncio
import html
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from rcscan.active_web.engine import ActiveWebSecurityEngine
from rcscan.active_web.models import ActiveWebCheckContext, ActiveWebSession
from rcscan.active_web.rules.traversal.rule import AdaptivePathTraversalCheck
from rcscan.web.http import WebHttpClient, WebResponse
from rcscan.web.models import (
    ParameterSource,
    WebDiscoveryResult,
    WebEndpoint,
    WebForm,
    WebParameter,
)

NOW = datetime(2026, 1, 2, tzinfo=UTC)


def discovery(
    *endpoints: WebEndpoint,
    origin: str = "http://site.example",
    forms: tuple[WebForm, ...] = (),
) -> WebDiscoveryResult:
    return WebDiscoveryResult(
        origin=origin,
        connect_host="203.0.113.10",
        pages_crawled=len(endpoints),
        endpoints=endpoints,
        forms=forms,
        started_at=NOW,
        completed_at=NOW,
    )


def endpoint(
    url: str = "http://site.example/product?id=1",
    *,
    body: str = "normal product",
    content_type: str = "text/html",
) -> WebEndpoint:
    parsed = urlsplit(url)
    names = tuple(parse_qs(parsed.query, keep_blank_values=True))
    return WebEndpoint(
        url=url,
        path=f"{parsed.path}?{parsed.query}",
        depth=1,
        status_code=200,
        content_type=content_type,
        response_headers={"content-type": content_type},
        body_preview=body,
        query_parameters=tuple(
            WebParameter(name=name, source=ParameterSource.QUERY) for name in names
        ),
    )


def get_form(
    *,
    action: str = "http://site.example/",
    names: tuple[str, ...] = ("search",),
    method: str = "GET",
) -> WebForm:
    return WebForm(
        page_url="http://site.example/",
        method=method,
        action_url=action,
        inputs=tuple(
            WebParameter(
                name=name,
                source=ParameterSource.FORM,
                input_type="search" if name == "search" else "text",
            )
            for name in names
        ),
    )


class FakeClient:
    def __init__(self, handler: Any) -> None:
        self.handler = handler
        self.calls: list[tuple[str, str]] = []

    async def get(self, url: str, *, connect_host: str) -> WebResponse:
        self.calls.append((url, connect_host))
        result = self.handler(url)
        if isinstance(result, BaseException):
            raise result
        return result


def engine(
    client: object,
    *,
    per_parameter: int = 4,
    total: int = 30,
    concurrency: int = 2,
    checks: tuple[object, ...] | None = None,
) -> ActiveWebSecurityEngine:
    return ActiveWebSecurityEngine(
        timeout_seconds=3,
        max_response_bytes=262_144,
        max_requests_per_parameter=per_parameter,
        max_total_requests=total,
        concurrency=concurrency,
        checks=checks,  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
    )


def normal(_url: str) -> WebResponse:
    return WebResponse(
        status_code=200,
        headers={"content-type": "text/html"},
        body=b"normal response",
    )


def test_no_discovered_parameters_makes_zero_active_requests() -> None:
    client = FakeClient(normal)
    result = asyncio.run(
        engine(client).analyze(
            (discovery(endpoint("http://site.example/about")),)
        )
    )
    assert result == ()
    assert client.calls == []


def test_get_form_input_becomes_active_target() -> None:
    client = FakeClient(normal)
    root = endpoint("http://site.example/")
    asyncio.run(
        engine(client).analyze(
            (discovery(root, forms=(get_form(),)),)
        )
    )
    assert client.calls
    assert all(
        "search" in parse_qs(urlsplit(url).query, keep_blank_values=True)
        for url, _host in client.calls
    )


def test_multiple_get_form_inputs_are_mutated_one_at_a_time() -> None:
    client = FakeClient(normal)
    root = endpoint("http://site.example/")
    asyncio.run(
        engine(client, total=20).analyze(
            (
                discovery(
                    root,
                    forms=(get_form(names=("search", "category")),),
                ),
            )
        )
    )
    assert client.calls
    for url, _host in client.calls:
        values = parse_qs(urlsplit(url).query, keep_blank_values=True)
        assert set(values) == {"search", "category"}
        assert sum(bool(value[0]) for value in values.values()) == 1


def test_external_get_form_action_is_blocked() -> None:
    client = FakeClient(normal)
    result = asyncio.run(
        engine(client).analyze(
            (
                discovery(
                    endpoint("http://site.example/"),
                    forms=(
                        get_form(action="https://outside.example/search"),
                    ),
                ),
            )
        )
    )
    assert result == ()
    assert client.calls == []


def test_query_and_form_target_are_deduplicated() -> None:
    client = FakeClient(normal)
    query_endpoint = endpoint("http://site.example/search?search=hello")
    asyncio.run(
        engine(client).analyze(
            (
                discovery(
                    query_endpoint,
                    forms=(
                        get_form(action="http://site.example/search"),
                    ),
                ),
            )
        )
    )
    assert len(client.calls) == 4


def test_unsafe_reflected_get_form_input_produces_xss_finding() -> None:
    def handler(url: str) -> WebResponse:
        value = parse_qs(urlsplit(url).query, keep_blank_values=True)["search"][0]
        return WebResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=f"<p>{value}</p>".encode(),
        )

    findings = asyncio.run(
        engine(FakeClient(handler)).analyze(
            (
                discovery(
                    endpoint("http://site.example/", body="<form>search</form>"),
                    forms=(get_form(),),
                ),
            )
        )
    )
    assert any(
        finding.source == "active-web-potential-reflected-xss"
        and finding.metadata["parameter"] == "search"
        for finding in findings
    )


def test_safely_encoded_get_form_reflection_is_not_xss() -> None:
    def handler(url: str) -> WebResponse:
        value = parse_qs(urlsplit(url).query, keep_blank_values=True)["search"][0]
        return WebResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=f"<p>{html.escape(value)}</p>".encode(),
        )

    findings = asyncio.run(
        engine(FakeClient(handler)).analyze(
            (
                discovery(
                    endpoint("http://site.example/", body="<form>search</form>"),
                    forms=(get_form(),),
                ),
            )
        )
    )
    assert all(
        finding.source != "active-web-potential-reflected-xss"
        for finding in findings
    )


def test_sqli_strong_new_error_differential_produces_conservative_finding() -> None:
    def handler(url: str) -> WebResponse:
        value = parse_qs(urlsplit(url).query)["id"][0]
        body = (
            b"SQLSTATE[42000] synthetic parser error"
            if value.endswith("'")
            else b"normal"
        )
        return WebResponse(
            status_code=500 if value.endswith("'") else 200,
            headers={"content-type": "text/html"},
            body=body,
        )

    findings = asyncio.run(
        engine(FakeClient(handler)).analyze((discovery(endpoint()),))
    )
    sql = next(
        item for item in findings if item.source == "active-web-potential-sql-injection"
    )
    assert sql.metadata["category"] == "POTENTIAL_SQL_INJECTION"
    assert sql.cve_id is None and sql.cvss is None
    assert "Baseline HTTP 200" in sql.evidence[0].summary


@pytest.mark.parametrize(
    "modified",
    [
        WebResponse(
            status_code=500,
            headers={"content-type": "text/html"},
            body=b"generic internal server error",
        ),
        WebResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"x" * 10_000,
        ),
        WebResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"normal safe handling",
        ),
    ],
)
def test_sqli_generic_500_length_only_and_safe_handling_make_no_finding(
    modified: WebResponse,
) -> None:
    findings = asyncio.run(
        engine(FakeClient(lambda _url: modified)).analyze((discovery(endpoint()),))
    )
    assert all(
        item.source != "active-web-potential-sql-injection" for item in findings
    )


def test_boolean_sqli_baseline_matches_true_and_stable_false_differs() -> None:
    baseline = "<ul><li>Alpha</li><li>Beta</li><li>Gamma</li></ul>"

    def handler(url: str) -> WebResponse:
        value = parse_qs(urlsplit(url).query)["category"][0]
        body = (
            "<ul><li>No matching products</li></ul>"
            if "'1'='2" in value
            else baseline
        )
        return WebResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=body.encode(),
        )

    item = endpoint(
        "http://site.example/filter?category=Gifts",
        body=baseline,
    )
    findings = asyncio.run(
        engine(FakeClient(handler)).analyze((discovery(item),))
    )
    sql = next(
        finding
        for finding in findings
        if finding.source == "active-web-potential-sql-injection"
    )
    assert "Baseline and TRUE responses were equivalent" in sql.evidence[0].summary
    assert sql.metadata["parameter"] == "category"


def test_boolean_sqli_all_three_similar_is_not_reported() -> None:
    baseline = "<p>Stable catalog response</p>"
    item = endpoint(
        "http://site.example/filter?category=Gifts",
        body=baseline,
    )
    findings = asyncio.run(
        engine(
            FakeClient(
                lambda _url: WebResponse(
                    status_code=200,
                    headers={"content-type": "text/html"},
                    body=baseline.encode(),
                )
            )
        ).analyze((discovery(item),))
    )
    assert all(
        finding.source != "active-web-potential-sql-injection"
        for finding in findings
    )


def test_boolean_sqli_unstable_responses_are_not_reported() -> None:
    counter = 0

    def handler(_url: str) -> WebResponse:
        nonlocal counter
        counter += 1
        body = f"<p>random branch {counter} {'x' * (counter * 137)}</p>"
        return WebResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=body.encode(),
        )

    findings = asyncio.run(
        engine(FakeClient(handler)).analyze(
            (
                discovery(
                    endpoint(
                        "http://site.example/filter?category=Gifts",
                        body="<p>baseline stable catalog</p>",
                    )
                ),
            )
        )
    )
    assert all(
        finding.source != "active-web-potential-sql-injection"
        for finding in findings
    )


def test_boolean_sqli_unrelated_length_jitter_is_not_reported() -> None:
    baseline = "<p>Catalog generated at 123456 with stable products</p>"

    def handler(url: str) -> WebResponse:
        value = parse_qs(urlsplit(url).query)["category"][0]
        jitter = 987654 if "'1'='2" in value else 777777
        return WebResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=(
                f"<p>Catalog generated at {jitter} with stable products</p>"
            ).encode(),
        )

    findings = asyncio.run(
        engine(FakeClient(handler)).analyze(
            (
                discovery(
                    endpoint(
                        "http://site.example/filter?category=Gifts",
                        body=baseline,
                    )
                ),
            )
        )
    )
    assert all(
        finding.source != "active-web-potential-sql-injection"
        for finding in findings
    )


def test_only_one_parameter_is_mutated_per_request() -> None:
    client = FakeClient(normal)
    asyncio.run(
        engine(client).analyze(
            (discovery(endpoint("http://site.example/product?id=1&mode=safe")),)
        )
    )
    for url, _host in client.calls:
        values = parse_qs(urlsplit(url).query, keep_blank_values=True)
        changed = sum(
            values[name][0] != original
            for name, original in {"id": "1", "mode": "safe"}.items()
        )
        assert changed == 1


def test_unescaped_html_reflection_is_potential_xss() -> None:
    def handler(url: str) -> WebResponse:
        value = parse_qs(urlsplit(url).query)["q"][0]
        return WebResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=f"<p>{value}</p>".encode(),
        )

    findings = asyncio.run(
        engine(FakeClient(handler)).analyze(
            (discovery(endpoint("http://site.example/search?q=hello")),)
        )
    )
    assert any(
        item.source == "active-web-potential-reflected-xss" for item in findings
    )


@pytest.mark.parametrize(
    ("content_type", "mode"),
    [
        ("text/html", "escaped"),
        ("text/html", "absent"),
        ("text/plain", "raw"),
    ],
)
def test_encoded_absent_or_non_html_reflection_is_not_xss(
    content_type: str,
    mode: str,
) -> None:
    def handler(url: str) -> WebResponse:
        value = parse_qs(urlsplit(url).query)["q"][0]
        reflected = (
            html.escape(value)
            if mode == "escaped"
            else "not reflected"
            if mode == "absent"
            else value
        )
        return WebResponse(
            status_code=200,
            headers={"content-type": content_type},
            body=reflected.encode(),
        )

    findings = asyncio.run(
        engine(FakeClient(handler)).analyze(
            (discovery(endpoint("http://site.example/search?q=hello")),)
        )
    )
    assert all(
        item.source != "active-web-potential-reflected-xss" for item in findings
    )


def test_external_endpoint_and_redirect_are_not_followed() -> None:
    client = FakeClient(
        lambda _url: WebResponse(
            status_code=302,
            headers={
                "content-type": "text/html",
                "location": "https://outside.example/",
            },
        )
    )
    result = asyncio.run(
        engine(client).analyze(
            (
                discovery(
                    endpoint("https://outside.example/product?id=1")
                ),
                discovery(endpoint(), origin="http://site.example"),
            )
        )
    )
    assert result == ()
    assert all("outside.example" not in url for url, _host in client.calls)


def test_timeout_and_truncation_are_isolated() -> None:
    calls = 0

    def handler(_url: str) -> WebResponse:
        nonlocal calls
        calls += 1
        if calls == 1:
            return WebResponse(error="TimeoutError")
        return WebResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"SQLSTATE[42000]",
            truncated=True,
        )

    assert asyncio.run(
        engine(FakeClient(handler)).analyze((discovery(endpoint()),))
    ) == ()


class DynamicWriter:
    def __init__(self, reader: asyncio.StreamReader) -> None:
        self.reader = reader
        self.payload = b""
        self.closed = False
        self.waited = False

    def write(self, payload: bytes) -> None:
        self.payload += payload

    async def drain(self) -> None:
        body = b"x" * 2_000 + b"SQLSTATE[42000]"
        self.reader.feed_data(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body
        )
        self.reader.feed_eof()

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.waited = True


def test_active_transport_response_size_is_bounded_and_streams_close() -> None:
    async def scenario() -> tuple[tuple[object, ...], list[DynamicWriter]]:
        writers: list[DynamicWriter] = []

        async def connect(
            _host: str,
            _port: int,
        ) -> tuple[asyncio.StreamReader, Any]:
            reader = asyncio.StreamReader()
            writer = DynamicWriter(reader)
            writers.append(writer)
            return reader, writer

        client = WebHttpClient(
            timeout_seconds=1,
            max_response_bytes=1_024,
            plain_connector=connect,
        )
        findings = await engine(client).analyze((discovery(endpoint()),))
        return findings, writers

    findings, writers = asyncio.run(scenario())
    assert findings == ()
    assert len(writers) == 1
    assert all(writer.closed and writer.waited for writer in writers)


LOCAL_UNIX_MARKER = (
    b"root:x:0:0:root:/root:/bin/bash\n"
    b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    b"www-data:x:33:33:www:/var/www:/usr/sbin/nologin\n"
)


async def _serve_asset(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    calls: list[str],
    vulnerable: bool,
) -> None:
    try:
        request = await reader.readuntil(b"\r\n\r\n")
        target = request.splitlines()[0].split(b" ", 2)[1].decode("ascii")
        value = parse_qs(urlsplit(target).query)["name"][0]
        calls.append(value)
        body = (
            LOCAL_UNIX_MARKER
            if vulnerable and value == "../../../etc/passwd"
            else b"\xff\xd8\xff\xe0synthetic-jpeg"
        )
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: image/jpeg\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )
        await writer.drain()
    finally:
        writer.close()
        with suppress(ConnectionError, OSError):
            await writer.wait_closed()


def test_real_http_image_mime_body_reaches_traversal_classification() -> None:
    async def scenario() -> tuple[tuple[object, ...], list[str]]:
        calls: list[str] = []
        server = await asyncio.start_server(
            lambda reader, writer: _serve_asset(
                reader,
                writer,
                calls=calls,
                vulnerable=True,
            ),
            "127.0.0.1",
            0,
        )
        try:
            port = server.sockets[0].getsockname()[1]
            origin = f"http://localhost:{port}"
            resource = endpoint(f"{origin}/asset?name=picture.jpg").model_copy(
                update={
                    "status_code": None,
                    "content_type": None,
                    "response_headers": {},
                    "body_preview": "",
                    "discovered_via_resource": True,
                }
            )
            discovered = discovery(resource, origin=origin).model_copy(
                update={"connect_host": "127.0.0.1"}
            )
            findings = await ActiveWebSecurityEngine(
                timeout_seconds=1,
                max_response_bytes=1_024,
                max_requests_per_parameter=4,
                max_total_requests=10,
                concurrency=1,
                checks=(AdaptivePathTraversalCheck(),),
            ).analyze((discovered,))
            return findings, calls
        finally:
            server.close()
            await server.wait_closed()

    findings, calls = asyncio.run(scenario())
    assert len(findings) == 1
    assert findings[0].metadata["rule_family"] == "traversal-unix-canonical"
    assert findings[0].metadata["confirmation_status"] == "CONFIRMED_BY_REPEAT"
    assert calls == [
        "picture.jpg",
        "../../../etc/passwd",
        "../../../etc/passwd",
    ]


def test_real_http_image_mime_without_marker_is_safe() -> None:
    async def scenario() -> tuple[tuple[object, ...], list[str]]:
        calls: list[str] = []
        server = await asyncio.start_server(
            lambda reader, writer: _serve_asset(
                reader,
                writer,
                calls=calls,
                vulnerable=False,
            ),
            "127.0.0.1",
            0,
        )
        try:
            port = server.sockets[0].getsockname()[1]
            origin = f"http://localhost:{port}"
            resource = endpoint(f"{origin}/media?name=picture.jpg").model_copy(
                update={
                    "status_code": None,
                    "content_type": None,
                    "response_headers": {},
                    "body_preview": "",
                    "discovered_via_resource": True,
                }
            )
            discovered = discovery(resource, origin=origin).model_copy(
                update={"connect_host": "127.0.0.1"}
            )
            findings = await ActiveWebSecurityEngine(
                timeout_seconds=1,
                max_response_bytes=1_024,
                max_requests_per_parameter=4,
                max_total_requests=10,
                concurrency=1,
                checks=(AdaptivePathTraversalCheck(),),
            ).analyze((discovered,))
            return findings, calls
        finally:
            server.close()
            await server.wait_closed()

    findings, calls = asyncio.run(scenario())
    assert findings == ()
    assert len(calls) == 3


def test_active_transport_retains_only_bounded_binary_prefix() -> None:
    async def handler(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            body = b"x" * 4_096
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: image/jpeg\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            with suppress(ConnectionError, OSError):
                await writer.wait_closed()

    async def scenario() -> WebResponse:
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        try:
            port = server.sockets[0].getsockname()[1]
            return await WebHttpClient(
                timeout_seconds=1,
                max_response_bytes=64,
                retain_body_for_all_content_types=True,
            ).get(
                f"http://localhost:{port}/asset?name=picture.jpg",
                connect_host="127.0.0.1",
            )
        finally:
            server.close()
            await server.wait_closed()

    result = asyncio.run(scenario())
    assert result.body == b"x" * 64
    assert result.bytes_received == 64
    assert result.truncated


class RepeatingCheck:
    rule_id = "active-web-repeating-test"

    async def evaluate(
        self,
        context: ActiveWebCheckContext,
        session: ActiveWebSession,
    ) -> None:
        for index in range(20):
            await session.get(context, value_suffix=f"x{index}")
        return None


def test_per_parameter_and_total_request_budgets_are_hard() -> None:
    per_client = FakeClient(normal)
    asyncio.run(
        engine(
            per_client,
            per_parameter=3,
            total=30,
            checks=(RepeatingCheck(),),
        ).analyze((discovery(endpoint()),))
    )
    assert len(per_client.calls) == 3

    total_client = FakeClient(normal)
    asyncio.run(
        engine(
            total_client,
            per_parameter=4,
            total=3,
            checks=(RepeatingCheck(),),
        ).analyze(
            (
                discovery(
                    endpoint("http://site.example/a?id=1"),
                    endpoint("http://site.example/b?q=1"),
                ),
            )
        )
    )
    assert len(total_client.calls) == 3


class BlockingClient:
    def __init__(self) -> None:
        self.active = 0
        self.peak = 0
        self.release = asyncio.Event()
        self.started = asyncio.Event()

    async def get(self, _url: str, *, connect_host: str) -> WebResponse:
        del connect_host
        self.active += 1
        self.peak = max(self.peak, self.active)
        if self.peak >= 2:
            self.started.set()
        try:
            await self.release.wait()
            return normal("")
        finally:
            self.active -= 1


class OneRequestCheck:
    rule_id = "active-web-one-request-test"

    async def evaluate(
        self,
        context: ActiveWebCheckContext,
        session: ActiveWebSession,
    ) -> None:
        await session.get(context, value_suffix="x")
        return None


def test_active_request_concurrency_is_bounded() -> None:
    async def scenario() -> int:
        client = BlockingClient()
        task = asyncio.create_task(
            engine(
                client,
                concurrency=2,
                checks=(OneRequestCheck(),),
            ).analyze(
                (
                    discovery(
                        endpoint("http://site.example/a?id=1"),
                        endpoint("http://site.example/b?q=1"),
                        endpoint("http://site.example/c?x=1"),
                    ),
                )
            )
        )
        await asyncio.wait_for(client.started.wait(), timeout=1)
        client.release.set()
        await task
        return client.peak

    assert asyncio.run(scenario()) == 2


def test_cancellation_propagates_from_active_request() -> None:
    async def scenario() -> None:
        client = BlockingClient()
        task = asyncio.create_task(
            engine(client, checks=(OneRequestCheck(),)).analyze(
                (discovery(endpoint()),)
            )
        )
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())


def test_post_forms_are_never_submitted() -> None:
    client = FakeClient(normal)
    form = WebForm(
        page_url="http://site.example/",
        method="POST",
        action_url="http://site.example/login",
        inputs=(
            WebParameter(
                name="password",
                source=ParameterSource.FORM,
                input_type="password",
            ),
        ),
    )
    result = asyncio.run(
        engine(client).analyze((discovery(forms=(form,)),))
    )
    assert result == ()
    assert client.calls == []
