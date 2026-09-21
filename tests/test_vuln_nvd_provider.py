import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from rcscan.fingerprint.models import Confidence
from rcscan.vuln.errors import (
    ProviderRateLimitError,
    ProviderResponseError,
    ProviderUnavailableError,
)
from rcscan.vuln.models import Applicability, NormalizedIdentity
from rcscan.vuln.providers.nvd import NVDProvider, parse_nvd_response
from rcscan.vuln.versioning import match_affected_range


def identity(version: str = "1.10") -> NormalizedIdentity:
    return NormalizedIdentity(
        original_product="nginx",
        vendor="nginx",
        product="nginx",
        version=version,
        cpe23=f"cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
        confidence=Confidence.HIGH,
        reason="synthetic",
    )


def provider(
    handler,
    *,
    api_key: str | None = None,
    max_bytes: int = 100_000,
    max_references: int = 10,
    max_records: int = 100,
) -> tuple[NVDProvider, httpx.AsyncClient]:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    instance = NVDProvider(
        api_key=api_key,
        timeout_seconds=1,
        max_response_bytes=max_bytes,
        max_references=max_references,
        max_records=max_records,
        client=client,
    )
    instance._pace = AsyncMock()
    return instance, client


def response_document(cve: dict | None = None) -> dict:
    return {"vulnerabilities": [{"cve": cve or {"id": "CVE-2026-1000"}}]}


def test_search_uses_official_endpoint_bounded_cpe_query_and_optional_api_key() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"vulnerabilities": []})

    instance, client = provider(handler, api_key="secret-key")
    result = asyncio.run(instance.search_product(identity()))
    asyncio.run(client.aclose())

    request = requests[0]
    assert str(request.url).startswith(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    )
    assert dict(request.url.params) == {
        "cpeName": identity().cpe23,
        "resultsPerPage": "100",
    }
    assert request.headers["apiKey"] == "secret-key"
    serialized = str(request.url)
    assert "10.0.0.1" not in serialized
    assert "target" not in serialized.casefold()
    assert result.identity_key == identity().cache_key


def test_request_without_api_key_omits_api_key_header() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"vulnerabilities": []})

    instance, client = provider(handler)
    asyncio.run(instance.search_product(identity()))
    asyncio.run(client.aclose())
    assert "apiKey" not in seen[0].headers


@pytest.mark.parametrize(
    ("exception", "message"),
    [
        (httpx.ReadTimeout("timeout"), "timed out"),
        (httpx.ConnectError("dns failed"), "network request failed"),
    ],
)
def test_transport_failures_are_sanitized(
    exception: httpx.RequestError, message: str
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise exception

    instance, client = provider(handler, api_key="never-expose-this")
    with pytest.raises(ProviderUnavailableError, match=message) as caught:
        asyncio.run(instance.search_product(identity()))
    asyncio.run(client.aclose())
    assert "never-expose-this" not in str(caught.value)
    assert "dns failed" not in str(caught.value)


def test_429_honors_retry_after_then_succeeds_with_patched_sleep() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "2.5"})
        return httpx.Response(200, json={"vulnerabilities": []})

    instance, client = provider(handler)
    with patch("rcscan.vuln.providers.nvd.asyncio.sleep", new=AsyncMock()) as sleep:
        asyncio.run(instance.search_product(identity()))
    asyncio.run(client.aclose())
    sleep.assert_awaited_once_with(2.5)
    assert calls == 2


def test_repeated_429_raises_rate_limit_error() -> None:
    instance, client = provider(
        lambda _request: httpx.Response(429, headers={"Retry-After": "0"})
    )
    with (
        patch("rcscan.vuln.providers.nvd.asyncio.sleep", new=AsyncMock()),
        pytest.raises(ProviderRateLimitError, match="rate limit"),
    ):
        asyncio.run(instance.search_product(identity()))
    asyncio.run(client.aclose())


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (500, "temporarily unavailable"),
        (503, "temporarily unavailable"),
        (401, "credentials"),
        (403, "credentials"),
    ],
)
def test_http_failures_are_typed(status: int, message: str) -> None:
    instance, client = provider(lambda _request: httpx.Response(status))
    with (
        patch("rcscan.vuln.providers.nvd.asyncio.sleep", new=AsyncMock()),
        pytest.raises(ProviderUnavailableError, match=message),
    ):
        asyncio.run(instance.search_product(identity()))
    asyncio.run(client.aclose())


@pytest.mark.parametrize("content", [b"{", b"\xff"])
def test_malformed_json_is_rejected(content: bytes) -> None:
    instance, client = provider(lambda _request: httpx.Response(200, content=content))
    with pytest.raises(ProviderResponseError, match="malformed JSON"):
        asyncio.run(instance.search_product(identity()))
    asyncio.run(client.aclose())


def test_oversized_response_is_rejected() -> None:
    instance, client = provider(
        lambda _request: httpx.Response(200, content=b"x" * 1025),
        max_bytes=1024,
    )
    with pytest.raises(ProviderResponseError, match="exceeded"):
        asyncio.run(instance.search_product(identity()))
    asyncio.run(client.aclose())


@pytest.mark.parametrize("document", [[], {"vulnerabilities": {}}, "text"])
def test_invalid_response_shapes_are_rejected(document: object) -> None:
    with pytest.raises(ProviderResponseError):
        parse_nvd_response(document, max_references=10, max_records=10)


def test_partial_fields_get_safe_defaults() -> None:
    records = parse_nvd_response(
        response_document(), max_references=10, max_records=10
    )
    record = records[0]
    assert record.description == "No description supplied."
    assert record.references == ()
    assert record.cvss == ()
    assert record.affected == ()
    assert record.published is None


def test_parser_bounds_description_references_and_records() -> None:
    cve = {
        "id": "CVE-2026-1000",
        "descriptions": [{"lang": "en", "value": " word " * 1000}],
        "references": [
            {"url": f"https://example.test/{index}"} for index in range(20)
        ]
        + [{"url": "file:///etc/passwd"}, {"url": "not-a-url"}],
    }
    document = {
        "vulnerabilities": [
            {"cve": {**cve, "id": f"CVE-2026-{1000 + index}"}}
            for index in range(5)
        ]
    }
    records = parse_nvd_response(document, max_references=2, max_records=3)
    assert len(records) == 3
    assert len(records[0].description) <= 2000
    assert records[0].references == (
        "https://example.test/0",
        "https://example.test/1",
    )


def test_duplicate_and_invalid_cves_are_omitted() -> None:
    document = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2026-1000"}},
            {"cve": {"id": "CVE-2026-1000"}},
            {"cve": {"id": "not-cve"}},
            {"bad": "shape"},
        ]
    }
    records = parse_nvd_response(document, max_references=10, max_records=10)
    assert [item.cve_id for item in records] == ["CVE-2026-1000"]


def test_cvss31_is_parsed_and_malformed_metrics_are_skipped() -> None:
    cve = {
        "id": "CVE-2026-1000",
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N",
                    }
                },
                {"cvssData": {"version": "3.1"}},
            ]
        },
    }
    metric = parse_nvd_response(
        response_document(cve), max_references=10, max_records=10
    )[0].cvss
    assert len(metric) == 1
    assert (metric[0].version, metric[0].base_score) == ("3.1", 9.8)


def test_exact_and_ranged_cpe_matches_are_parsed() -> None:
    cve = {
        "id": "CVE-2026-1000",
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:nginx:nginx:1.10:*:*:*:*:*:*:*",
                            },
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.0",
                                "versionEndExcluding": "2.0",
                            },
                        ],
                    }
                ]
            }
        ],
    }
    affected = parse_nvd_response(
        response_document(cve), max_references=10, max_records=10
    )[0].affected
    assert len(affected) == 2
    assert affected[0].version == "1.10"
    assert match_affected_range(identity(), affected[0]) is Applicability.MATCH
    assert match_affected_range(identity(), affected[1]) is Applicability.MATCH
    assert match_affected_range(identity("2.0"), affected[1]) is Applicability.NO_MATCH


@pytest.mark.parametrize("condition", [{"operator": "AND"}, {"negate": True}])
def test_complex_configuration_marks_conditions_unverified(
    condition: dict[str, object]
) -> None:
    node = {
        **condition,
        "cpeMatch": [
            {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:nginx:nginx:1.10:*:*:*:*:*:*:*",
            }
        ],
    }
    cve = {
        "id": "CVE-2026-1000",
        "configurations": [{"nodes": [node]}],
    }
    affected = parse_nvd_response(
        response_document(cve), max_references=10, max_records=10
    )[0].affected
    assert affected[0].conditions_unverified is True


def test_application_plus_platform_configuration_is_conditional() -> None:
    cve = {
        "id": "CVE-2026-1000",
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:nginx:nginx:1.10:*:*:*:*:*:*:*",
                            },
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                            },
                        ],
                    }
                ]
            }
        ],
    }
    affected = parse_nvd_response(
        response_document(cve), max_references=10, max_records=10
    )[0].affected
    assert affected[0].conditions_unverified is True
