import asyncio
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, urlsplit

import pytest

from rcscan.active_web.engine import ActiveWebSecurityEngine
from rcscan.active_web.rules.traversal.rule import AdaptivePathTraversalCheck
from rcscan.core.config import (
    ActiveWebChecksConfig,
    AppConfig,
    WebChecksConfig,
    WebDiscoveryConfig,
)
from rcscan.fingerprint.models import Confidence, Service, ServiceFingerprint
from rcscan.models.scan import Scan, ScanStatus
from rcscan.network.models import (
    DiscoveryMethod,
    DiscoveryStatus,
    HostScanResult,
    PortResult,
    PortState,
)
from rcscan.scope.parser import parse_target
from rcscan.services.scan_runner import ScanRunner
from rcscan.web.crawler import WebCrawler
from rcscan.web.http import WebHttpClient, WebResponse
from rcscan.web.models import WebCookie, WebDiscoveryResult

NOW = datetime(2026, 1, 2, tzinfo=UTC)


def host(
    *,
    target: str = "site.example",
    address: str = "203.0.113.10",
    service: Service = Service.HTTP,
    port_number: int = 80,
) -> HostScanResult:
    fingerprint = ServiceFingerprint(
        service=service,
        confidence=Confidence.HIGH,
        evidence=(),
        probe_used="test",
        encrypted=service is Service.HTTPS,
    )
    port = PortResult(
        host=address,
        port=port_number,
        state=PortState.OPEN,
        latency_ms=1,
        timestamp=NOW,
        fingerprint=fingerprint,
    )
    return HostScanResult(
        target=target,
        resolved_address=address,
        discovery_status=DiscoveryStatus.SKIPPED,
        discovery_method=DiscoveryMethod.SKIPPED,
        discovery_latency_ms=None,
        ports=(port,),
        started_at=NOW,
        completed_at=NOW,
    )


def response(
    body: str = "",
    *,
    status: int = 200,
    content_type: str = "text/html",
    headers: dict[str, str] | None = None,
    **updates: Any,
) -> WebResponse:
    all_headers = {"content-type": content_type, **(headers or {})}
    return WebResponse(
        status_code=status,
        headers=all_headers,
        body=body.encode(),
        **updates,
    )


class FakeClient:
    def __init__(self, responses: dict[str, WebResponse] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, str]] = []

    async def get(self, url: str, *, connect_host: str) -> WebResponse:
        self.calls.append((url, connect_host))
        return self.responses.get(url, response())


def crawler(
    client: object,
    *,
    max_pages: int = 50,
    max_depth: int = 2,
    concurrency: int = 4,
    max_links_per_page: int = 100,
) -> WebCrawler:
    return WebCrawler(
        max_pages=max_pages,
        max_depth=max_depth,
        concurrency=concurrency,
        timeout_seconds=3,
        max_response_bytes=262_144,
        max_links_per_page=max_links_per_page,
        client=client,  # type: ignore[arg-type]
    )


def scan() -> Scan:
    target = parse_target("10.0.0.1")
    return Scan(
        targets=(target,),
        authorized_scope=(target,),
        profile_name="test",
        ports=(80,),
        authorization_confirmed=True,
    )


def runner_dependencies() -> tuple[AsyncMock, AsyncMock, MagicMock, AsyncMock]:
    scanned_port = host(target="10.0.0.1", address="10.0.0.1").ports[0]
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (scanned_port,)
    fingerprinter = AsyncMock()
    fingerprinter.fingerprint_ports.return_value = (scanned_port,)
    findings = MagicMock()
    findings.generate.return_value = ()
    web = AsyncMock()
    web.discover.return_value = ()
    return scanner, fingerprinter, findings, web


@pytest.mark.parametrize(
    ("configured", "flag", "expected"),
    [(False, False, 0), (False, True, 1), (True, False, 1)],
)
def test_runner_web_discovery_requires_explicit_enablement(
    configured: bool,
    flag: bool,
    expected: int,
) -> None:
    scanner, fingerprinter, findings, web = runner_dependencies()
    result = asyncio.run(
        ScanRunner(
            AppConfig(web_discovery=WebDiscoveryConfig(enabled=configured)),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            finding_engine=findings,
            web_crawler=web,
        ).run(scan(), skip_discovery=True, web_discovery=flag)
    )
    assert result.status is ScanStatus.COMPLETED
    assert web.discover.await_count == expected


def test_web_checks_disabled_produces_zero_web_findings() -> None:
    scanner, fingerprinter, findings, web = runner_dependencies()
    security = MagicMock()
    active_security = AsyncMock()
    result = asyncio.run(
        ScanRunner(
            AppConfig(),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            finding_engine=findings,
            web_crawler=web,
            web_security_engine=security,
            active_web_security_engine=active_security,
        ).run(scan(), skip_discovery=True)
    )
    assert result.web_findings == ()
    web.discover.assert_not_awaited()
    security.analyze.assert_not_called()
    active_security.analyze.assert_not_awaited()
    assert result.active_web_findings == ()


def test_web_checks_automatically_enable_discovery() -> None:
    scanner, fingerprinter, findings, web = runner_dependencies()
    discovered = WebDiscoveryResult(
        origin="http://10.0.0.1",
        started_at=NOW,
        completed_at=NOW,
    )
    web.discover.return_value = (discovered,)
    security = MagicMock()
    security.analyze.return_value = ()
    result = asyncio.run(
        ScanRunner(
            AppConfig(web_checks=WebChecksConfig(enabled=True)),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            finding_engine=findings,
            web_crawler=web,
            web_security_engine=security,
        ).run(scan(), skip_discovery=True)
    )
    assert result.status is ScanStatus.COMPLETED
    web.discover.assert_awaited_once()
    security.analyze.assert_called_once_with((discovered,))


def test_active_web_checks_automatically_enable_discovery() -> None:
    scanner, fingerprinter, findings, web = runner_dependencies()
    discovered = WebDiscoveryResult(
        origin="http://10.0.0.1",
        started_at=NOW,
        completed_at=NOW,
    )
    web.discover.return_value = (discovered,)
    active_security = AsyncMock()
    active_security.analyze.return_value = ()
    result = asyncio.run(
        ScanRunner(
            AppConfig(active_web_checks=ActiveWebChecksConfig(enabled=True)),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            finding_engine=findings,
            web_crawler=web,
            active_web_security_engine=active_security,
        ).run(scan(), skip_discovery=True)
    )
    assert result.status is ScanStatus.COMPLETED
    web.discover.assert_awaited_once()
    active_security.analyze.assert_awaited_once_with((discovered,))


def test_runner_isolates_web_discovery_failure() -> None:
    scanner, fingerprinter, findings, web = runner_dependencies()
    web.discover.side_effect = RuntimeError("isolated")
    result = asyncio.run(
        ScanRunner(
            AppConfig(web_discovery=WebDiscoveryConfig(enabled=True)),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            finding_engine=findings,
            web_crawler=web,
        ).run(scan(), skip_discovery=True)
    )
    assert result.status is ScanStatus.COMPLETED
    assert result.hosts[0].ports
    assert result.web_discovery_results == ()


def test_runner_isolates_whole_web_check_stage_failure() -> None:
    scanner, fingerprinter, findings, web = runner_dependencies()
    discovered = WebDiscoveryResult(
        origin="http://10.0.0.1",
        started_at=NOW,
        completed_at=NOW,
    )
    web.discover.return_value = (discovered,)
    security = MagicMock()
    security.analyze.side_effect = RuntimeError("isolated")
    result = asyncio.run(
        ScanRunner(
            AppConfig(web_checks=WebChecksConfig(enabled=True)),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            finding_engine=findings,
            web_crawler=web,
            web_security_engine=security,
        ).run(scan(), skip_discovery=True)
    )
    assert result.status is ScanStatus.COMPLETED
    assert result.web_discovery_results == (discovered,)
    assert result.web_findings == ()


def test_runner_isolates_whole_active_web_check_stage_failure() -> None:
    scanner, fingerprinter, findings, web = runner_dependencies()
    discovered = WebDiscoveryResult(
        origin="http://10.0.0.1",
        started_at=NOW,
        completed_at=NOW,
    )
    web.discover.return_value = (discovered,)
    active_security = AsyncMock()
    active_security.analyze.side_effect = RuntimeError("isolated")
    result = asyncio.run(
        ScanRunner(
            AppConfig(active_web_checks=ActiveWebChecksConfig(enabled=True)),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            finding_engine=findings,
            web_crawler=web,
            active_web_security_engine=active_security,
        ).run(scan(), skip_discovery=True)
    )
    assert result.status is ScanStatus.COMPLETED
    assert result.web_discovery_results == (discovered,)
    assert result.active_web_findings == ()


def test_runner_web_discovery_cancellation_marks_scan_cancelled() -> None:
    scanner, fingerprinter, findings, web = runner_dependencies()
    web.discover.side_effect = asyncio.CancelledError
    runner = ScanRunner(
        AppConfig(web_discovery=WebDiscoveryConfig(enabled=True)),
        scanner=scanner,
        fingerprint_engine=fingerprinter,
        finding_engine=findings,
        web_crawler=web,
    )
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(runner.run(scan(), skip_discovery=True))
    assert runner.current_scan is not None
    assert runner.current_scan.status is ScanStatus.CANCELLED


def test_same_origin_crawl_blocks_external_links_and_deduplicates_query_shapes() -> None:
    root = "http://site.example"
    client = FakeClient(
        {
            f"{root}/": response(
                """
                <a href="/items?id=1#fragment">one</a>
                <a href="/items?id=2">duplicate shape</a>
                <a href="https://outside.example/steal">external</a>
                <a href="mailto:test@example.com">mail</a>
                """
            ),
        }
    )
    result = asyncio.run(crawler(client).discover((host(),)))[0]
    called = [url for url, _connect_host in client.calls]
    assert f"{root}/items?id=1" in called
    assert f"{root}/items?id=2" not in called
    assert all("outside.example" not in url for url in called)
    assert result.query_parameter_count == 1


def test_crawler_retains_bounded_sanitized_passive_security_evidence() -> None:
    root = "http://site.example"
    client = FakeClient(
        {
            f"{root}/": WebResponse(
                status_code=200,
                headers={
                    "content-type": "text/html",
                    "server": "DemoServer/1.2.3",
                    "x-unrelated": "discard me",
                },
                cookies=(WebCookie(name="sessionid"),),
                body=b"synthetic bounded error",
            )
        }
    )
    result = asyncio.run(crawler(client).discover((host(),)))[0]
    root_endpoint = next(item for item in result.endpoints if item.path == "/")
    assert root_endpoint.response_headers["server"] == "DemoServer/1.2.3"
    assert "x-unrelated" not in root_endpoint.response_headers
    assert root_endpoint.cookies[0].name == "sessionid"
    assert root_endpoint.body_preview == "synthetic bounded error"


def test_external_redirect_is_not_followed() -> None:
    root = "http://site.example"
    client = FakeClient(
        {
            f"{root}/": response(
                status=302,
                headers={"location": "https://outside.example/redirected"},
            )
        }
    )
    asyncio.run(crawler(client).discover((host(),)))
    assert all("outside.example" not in url for url, _host in client.calls)


def test_depth_limit_prevents_deeper_requests() -> None:
    root = "http://site.example"
    client = FakeClient(
        {
            f"{root}/": response('<a href="/one">one</a>'),
            f"{root}/one": response('<a href="/two">two</a>'),
            f"{root}/two": response('<a href="/three">three</a>'),
        }
    )
    asyncio.run(crawler(client, max_depth=1).discover((host(),)))
    called = {url for url, _host in client.calls}
    assert f"{root}/one" in called
    assert f"{root}/two" not in called


def test_page_limit_is_hard() -> None:
    root = "http://site.example"
    links = "".join(f'<a href="/page-{index}">x</a>' for index in range(20))
    client = FakeClient({f"{root}/": response(links)})
    result = asyncio.run(crawler(client, max_pages=4).discover((host(),)))[0]
    assert len(client.calls) == 4
    assert result.pages_crawled == 4
    assert len(result.endpoints) > result.pages_crawled


def test_page_limit_is_global_across_multiple_origins() -> None:
    client = FakeClient()
    results = asyncio.run(
        crawler(client, max_pages=4).discover(
            (
                host(target="one.example", address="203.0.113.10"),
                host(target="two.example", address="203.0.113.11"),
            )
        )
    )
    assert sum(result.pages_crawled for result in results) == 4
    assert len(client.calls) == 4


def test_forms_inputs_query_scripts_resources_and_api_references_are_structured() -> None:
    root = "http://site.example"
    client = FakeClient(
        {
            f"{root}/": response(
                """
                <form method="get" action="/search">
                  <input name="q" type="search">
                </form>
                <form method="post" action="/login">
                  <input name="user"><input name="password" type="password">
                </form>
                <script src="/static/app.js"></script>
                <link rel="stylesheet" href="/static/app.css">
                <a href="/view?page=1">view</a>
                <script>const endpoint = "/api/v1/users?limit=5";</script>
                """
            )
        }
    )
    result = asyncio.run(crawler(client).discover((host(),)))[0]
    assert [(form.method, form.action_url) for form in result.forms] == [
        ("GET", f"{root}/search"),
        ("POST", f"{root}/login"),
    ]
    assert [parameter.name for parameter in result.forms[1].inputs] == [
        "user",
        "password",
    ]
    assert result.scripts == (f"{root}/static/app.js",)
    assert result.resources == (f"{root}/static/app.css",)
    called = {url for url, _host in client.calls}
    assert f"{root}/view?page=1" in called
    assert f"{root}/api/v1/users?limit=5" in called
    assert f"{root}/login" not in called


def test_query_bearing_html_resources_become_unfetched_discovered_endpoints() -> None:
    root = "http://site.example"
    client = FakeClient(
        {
            f"{root}/": response(
                """
                <img src="/asset?filename=test.png">
                <img src="/asset?filename=test.png#duplicate">
                <source src="media/render?variant=small">
                <script src="/bundle?version=7"></script>
                <link rel="stylesheet" href="/style?theme=light">
                <img src="/plain.png">
                <img src="https://outside.example/image?filename=external.png">
                """
            )
        }
    )
    result = asyncio.run(crawler(client).discover((host(),)))[0]
    resource_endpoints = [
        endpoint for endpoint in result.endpoints if endpoint.discovered_via_resource
    ]
    urls = [endpoint.url for endpoint in resource_endpoints]

    assert urls.count(f"{root}/asset?filename=test.png") == 1
    assert f"{root}/media/render?variant=small" in urls
    assert f"{root}/bundle?version=7" in urls
    assert f"{root}/style?theme=light" in urls
    asset = next(
        endpoint
        for endpoint in resource_endpoints
        if endpoint.url == f"{root}/asset?filename=test.png"
    )
    assert [parameter.name for parameter in asset.query_parameters] == ["filename"]
    assert all("outside.example" not in url for url in urls)
    assert all(endpoint.url != f"{root}/plain.png" for endpoint in result.endpoints)
    assert f"{root}/plain.png" in result.resources
    called = {url for url, _connect_host in client.calls}
    assert all(url not in called for url in urls)


def test_resource_endpoint_discovery_obeys_per_page_link_bound() -> None:
    root = "http://site.example"
    references = "".join(
        f'<img src="/asset-{index}?variant={index}">'
        for index in range(10)
    )
    result = asyncio.run(
        crawler(
            FakeClient({f"{root}/": response(references)}),
            max_links_per_page=3,
        ).discover((host(),))
    )[0]
    resource_endpoints = [
        endpoint for endpoint in result.endpoints if endpoint.discovered_via_resource
    ]
    assert len(resource_endpoints) == 3


def test_binary_img_baseline_reaches_adaptive_traversal_pipeline() -> None:
    root = "http://site.example"
    discovery_client = FakeClient(
        {
            f"{root}/": response(
                '<img src="/asset?name=picture.jpg">'
            )
        }
    )
    discovered = asyncio.run(crawler(discovery_client).discover((host(),)))[0]
    resource_url = f"{root}/asset?name=picture.jpg"
    resource_endpoint = next(
        endpoint for endpoint in discovered.endpoints if endpoint.url == resource_url
    )
    assert resource_endpoint.discovered_via_resource
    assert resource_url not in {
        url for url, _connect_host in discovery_client.calls
    }

    unix_marker = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www:/var/www:/usr/sbin/nologin\n"
    )

    class ActiveClient:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def get(self, url: str, *, connect_host: str) -> WebResponse:
            assert connect_host == "203.0.113.10"
            self.calls.append(url)
            value = parse_qs(urlsplit(url).query)["name"][0]
            if value == "../../../etc/passwd":
                return response(unix_marker, content_type="text/plain")
            return WebResponse(
                status_code=200,
                headers={"content-type": "image/jpeg"},
                body=b"\xff\xd8\xff\xe0synthetic-image",
            )

    active_client = ActiveClient()
    findings = asyncio.run(
        ActiveWebSecurityEngine(
            timeout_seconds=3,
            max_response_bytes=262_144,
            max_requests_per_parameter=4,
            max_total_requests=30,
            concurrency=2,
            checks=(AdaptivePathTraversalCheck(),),
            client=active_client,  # type: ignore[arg-type]
        ).analyze((discovered,))
    )
    assert len(findings) == 1
    assert findings[0].metadata["parameter"] == "name"
    assert findings[0].metadata["rule_family"] == "traversal-unix-canonical"
    assert active_client.calls[0] == resource_url
    assert len(active_client.calls) == 3


def test_binary_img_baseline_safe_endpoint_produces_zero_traversal_findings() -> None:
    root = "http://site.example"
    discovery_client = FakeClient(
        {
            f"{root}/": response(
                '<img src="/media?name=picture.jpg">'
            )
        }
    )
    discovered = asyncio.run(crawler(discovery_client).discover((host(),)))[0]

    class SafeActiveClient:
        async def get(self, url: str, *, connect_host: str) -> WebResponse:
            assert urlsplit(url).path == "/media"
            assert connect_host == "203.0.113.10"
            return WebResponse(
                status_code=200,
                headers={"content-type": "image/jpeg"},
                body=b"\xff\xd8\xff\xe0stable-safe-image",
            )

    findings = asyncio.run(
        ActiveWebSecurityEngine(
            timeout_seconds=3,
            max_response_bytes=262_144,
            max_requests_per_parameter=4,
            max_total_requests=30,
            concurrency=2,
            checks=(AdaptivePathTraversalCheck(),),
            client=SafeActiveClient(),  # type: ignore[arg-type]
        ).analyze((discovered,))
    )
    assert findings == ()


def test_robots_and_sitemap_are_discovered_without_crawling_disallow_entries() -> None:
    root = "http://site.example"
    client = FakeClient(
        {
            f"{root}/robots.txt": response(
                "User-agent: *\nDisallow: /private\nAllow: /public\n"
                f"Sitemap: {root}/sitemap.xml\n",
                content_type="text/plain",
            ),
            f"{root}/sitemap.xml": response(
                f"<urlset><url><loc>{root}/from-map</loc></url></urlset>",
                content_type="application/xml",
            ),
        }
    )
    result = asyncio.run(crawler(client).discover((host(),)))[0]
    assert "Disallow: /private" in result.robots_entries
    assert result.sitemap_urls == (f"{root}/from-map",)
    called = {url for url, _host in client.calls}
    assert f"{root}/from-map" in called
    assert f"{root}/private" not in called


@pytest.mark.parametrize(
    "web_response",
    [
        WebResponse(error="TimeoutError", duration_ms=1),
        response("<html><form><input name='x'", content_type="text/html"),
        response("binary", content_type="application/octet-stream"),
    ],
)
def test_timeout_malformed_html_and_binary_content_are_isolated(
    web_response: WebResponse,
) -> None:
    root = "http://site.example"
    client = FakeClient({f"{root}/": web_response})
    result = asyncio.run(crawler(client).discover((host(),)))[0]
    assert result.pages_crawled >= 1
    assert all(url != f"{root}/x" for url, _host in client.calls)


def test_https_preserves_hostname_for_origin_and_resolved_address_for_connection() -> None:
    client = FakeClient()
    result = asyncio.run(
        crawler(client).discover(
            (
                host(
                    target="secure.example",
                    address="203.0.113.20",
                    service=Service.HTTPS,
                    port_number=443,
                ),
            )
        )
    )[0]
    assert result.origin == "https://secure.example"
    assert all(connect_host == "203.0.113.20" for _url, connect_host in client.calls)


def test_unconfirmed_service_makes_zero_crawler_requests() -> None:
    client = FakeClient()
    assert asyncio.run(crawler(client).discover((host(service=Service.SSH),))) == ()
    assert client.calls == []


class FakeWriter:
    def __init__(self) -> None:
        self.closed = False
        self.waited = False
        self.payload = b""

    def write(self, payload: bytes) -> None:
        self.payload += payload

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.waited = True


def reader_with(payload: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


def test_http_transport_bounds_response_size_and_closes_stream() -> None:
    writer = FakeWriter()

    async def connect(_host: str, _port: int) -> tuple[asyncio.StreamReader, Any]:
        return (
            reader_with(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                + b"x" * 2_000
            ),
            writer,
        )

    result = asyncio.run(
        WebHttpClient(
            timeout_seconds=1,
            max_response_bytes=1_024,
            plain_connector=connect,
        ).get("http://site.example/", connect_host="203.0.113.10")
    )
    assert result.truncated
    assert len(result.body) == 1_024
    assert writer.closed and writer.waited
    assert writer.payload.startswith(b"GET / HTTP/1.1\r\nHost: site.example\r\n")


def test_https_transport_preserves_hostname_sni_and_connects_to_resolved_address() -> None:
    async def scenario() -> tuple[WebResponse, list[dict[str, object]], FakeWriter]:
        calls: list[dict[str, object]] = []
        writer = FakeWriter()

        async def tls(hostname: str, port: int, **kwargs: object):
            calls.append({"host": hostname, "port": port, **kwargs})
            return (
                reader_with(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok"
                ),
                writer,
            )

        result = await WebHttpClient(
            timeout_seconds=1,
            max_response_bytes=1_024,
            tls_connector=tls,
        ).get("https://secure.example/", connect_host="203.0.113.20")
        return result, calls, writer

    result, calls, writer = asyncio.run(scenario())
    assert result.status_code == 200
    assert calls[0]["host"] == "203.0.113.20"
    assert calls[0]["server_hostname"] == "secure.example"
    assert writer.payload.startswith(b"GET / HTTP/1.1\r\nHost: secure.example\r\n")


def test_http_timeout_is_bounded_and_closes_stream() -> None:
    async def scenario() -> tuple[WebResponse, FakeWriter]:
        writer = FakeWriter()
        reader = asyncio.StreamReader()

        async def connect(_host: str, _port: int) -> tuple[asyncio.StreamReader, Any]:
            return reader, writer

        result = await WebHttpClient(
            timeout_seconds=0.01,
            max_response_bytes=1_024,
            plain_connector=connect,
        ).get("http://site.example/", connect_host="203.0.113.10")
        return result, writer

    result, writer = asyncio.run(scenario())
    assert result.error is not None and "TimeoutError" in result.error
    assert writer.closed and writer.waited


def test_binary_response_body_is_not_downloaded() -> None:
    async def scenario() -> tuple[WebResponse, FakeWriter]:
        writer = FakeWriter()
        reader = asyncio.StreamReader()
        reader.feed_data(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n"
        )

        async def connect(_host: str, _port: int) -> tuple[asyncio.StreamReader, Any]:
            return reader, writer

        result = await WebHttpClient(
            timeout_seconds=1,
            max_response_bytes=1_024,
            plain_connector=connect,
        ).get("http://site.example/download", connect_host="203.0.113.10")
        return result, writer

    result, writer = asyncio.run(scenario())
    assert result.status_code == 200
    assert result.body == b""
    assert writer.closed and writer.waited


def test_cancellation_propagates_after_stream_cleanup() -> None:
    async def scenario() -> FakeWriter:
        writer = FakeWriter()
        reader = asyncio.StreamReader()

        async def connect(_host: str, _port: int) -> tuple[asyncio.StreamReader, Any]:
            return reader, writer

        task = asyncio.create_task(
            WebHttpClient(
                timeout_seconds=5,
                max_response_bytes=1_024,
                plain_connector=connect,
            ).get("http://site.example/", connect_host="203.0.113.10")
        )
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return writer

    writer = asyncio.run(scenario())
    assert writer.closed and writer.waited
