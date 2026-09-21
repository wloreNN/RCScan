import asyncio
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from rcscan.active_web.engine import ActiveWebSecurityEngine
from rcscan.active_web.models import ActiveWebCheckContext
from rcscan.active_web.rules.traversal.models import TraversalPlatform
from rcscan.active_web.rules.traversal.rule import AdaptivePathTraversalCheck
from rcscan.active_web.rules.traversal.selection import (
    classify_eligibility,
    infer_platform,
    select_variants,
)
from rcscan.active_web.rules.traversal.signatures import match_standard_marker
from rcscan.web.http import WebResponse
from rcscan.web.models import (
    ParameterSource,
    WebDiscoveryResult,
    WebEndpoint,
    WebForm,
    WebParameter,
)

NOW = datetime(2026, 1, 2, tzinfo=UTC)
UNIX_MARKER = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www:/var/www:/usr/sbin/nologin
"""
WINDOWS_MARKER = """\
; synthetic Windows initialization marker
[fonts]
[extensions]
[mci extensions]
"""


def endpoint(
    url: str = "http://site.example/download?file=manual.pdf",
    *,
    body: str = "normal download page",
    server: str = "",
) -> WebEndpoint:
    parsed = urlsplit(url)
    parameters = tuple(parse_qs(parsed.query, keep_blank_values=True))
    headers = {"content-type": "text/html"}
    if server:
        headers["server"] = server
    return WebEndpoint(
        url=url,
        path=f"{parsed.path}?{parsed.query}",
        depth=1,
        status_code=200,
        content_type="text/html",
        response_headers=headers,
        body_preview=body,
        query_parameters=tuple(
            WebParameter(name=name, source=ParameterSource.QUERY)
            for name in parameters
        ),
    )


def discovery(
    item: WebEndpoint,
    *,
    forms: tuple[WebForm, ...] = (),
) -> WebDiscoveryResult:
    return WebDiscoveryResult(
        origin="http://site.example",
        connect_host="203.0.113.10",
        pages_crawled=1,
        endpoints=(item,),
        forms=forms,
        started_at=NOW,
        completed_at=NOW,
    )


def context(item: WebEndpoint | None = None) -> ActiveWebCheckContext:
    selected = item or endpoint()
    return ActiveWebCheckContext(
        discovery=discovery(selected),
        endpoint=selected,
        parameter=selected.query_parameters[0].name,
    )


class FakeClient:
    def __init__(self, handler: Any) -> None:
        self.handler = handler
        self.calls: list[str] = []

    async def get(self, url: str, *, connect_host: str) -> WebResponse:
        assert connect_host == "203.0.113.10"
        self.calls.append(url)
        return self.handler(url, len(self.calls))


def traversal_engine(
    client: object,
    *,
    per_parameter: int = 4,
) -> ActiveWebSecurityEngine:
    return ActiveWebSecurityEngine(
        timeout_seconds=3,
        max_response_bytes=262_144,
        max_requests_per_parameter=per_parameter,
        max_total_requests=30,
        concurrency=2,
        checks=(AdaptivePathTraversalCheck(),),
        client=client,  # type: ignore[arg-type]
    )


def response(
    body: str = "normal download page",
    *,
    status: int = 200,
    content_type: str = "text/html",
) -> WebResponse:
    return WebResponse(
        status_code=status,
        headers={"content-type": content_type},
        body=body.encode(),
    )


@pytest.mark.parametrize(
    ("marker", "platform"),
    [
        (UNIX_MARKER, TraversalPlatform.UNIX),
        (WINDOWS_MARKER, TraversalPlatform.WINDOWS),
    ],
)
def test_structured_marker_signatures_are_strong_and_explainable(
    marker: str,
    platform: TraversalPlatform,
) -> None:
    match = match_standard_marker(marker)
    assert match is not None
    assert match.platform is platform
    assert len(match.reason) > 20


@pytest.mark.parametrize(
    "weak",
    [
        "root",
        "windows file not found",
        "root:x:0:0",
        "[fonts]\n",
        "generic server error",
    ],
)
def test_generic_keywords_do_not_match_marker_signatures(weak: str) -> None:
    assert match_standard_marker(weak) is None


def test_windows_evidence_prioritizes_windows_family() -> None:
    item = endpoint(server="Microsoft-IIS/10.0")
    selected = select_variants(context(item))
    assert infer_platform(context(item)) is TraversalPlatform.WINDOWS
    assert selected[0].platform is TraversalPlatform.WINDOWS
    assert any(variant.platform is TraversalPlatform.UNIX for variant in selected)


def test_unix_evidence_prioritizes_unix_family() -> None:
    item = endpoint(server="nginx/1.24.0")
    selected = select_variants(context(item))
    assert infer_platform(context(item)) is TraversalPlatform.UNIX
    assert selected[0].platform is TraversalPlatform.UNIX
    assert any(variant.platform is TraversalPlatform.WINDOWS for variant in selected)


def test_unknown_platform_begins_with_cross_platform_initial_rules() -> None:
    selected = select_variants(context(endpoint(server="DemoServer/1.0")))
    assert [variant.platform for variant in selected[:2]] == [
        TraversalPlatform.UNIX,
        TraversalPlatform.WINDOWS,
    ]
    assert all(variant.initial for variant in selected[:2])


def test_parameter_and_existing_value_eligibility_is_explainable() -> None:
    named = classify_eligibility(context(endpoint()))
    value_based = classify_eligibility(
        context(endpoint("http://site.example/get?id=reports/manual.pdf"))
    )
    unrelated = classify_eligibility(
        context(endpoint("http://site.example/product?id=9"))
    )
    assert named.eligible and named.score >= 3 and named.reasons
    assert value_based.eligible and value_based.score >= 2
    assert not unrelated.eligible


def test_unrelated_parameter_is_skipped_without_requests() -> None:
    client = FakeClient(lambda _url, _count: response())
    findings = asyncio.run(
        traversal_engine(client).analyze(
            (discovery(endpoint("http://site.example/product?id=9")),)
        )
    )
    assert findings == ()
    assert client.calls == []


def test_strong_unix_signature_requires_repeat_confirmation() -> None:
    client = FakeClient(lambda _url, _count: response(UNIX_MARKER))
    findings = asyncio.run(
        traversal_engine(client).analyze((discovery(endpoint()),))
    )
    assert len(client.calls) == 2
    finding = findings[0]
    assert finding.metadata["category"] == "POTENTIAL_PATH_TRAVERSAL"
    assert finding.metadata["parameter"] == "file"
    assert finding.metadata["rule_family"] == "traversal-unix-canonical"
    assert finding.metadata["platform"] == "UNIX"
    assert finding.metadata["confirmation_status"] == "CONFIRMED_BY_REPEAT"
    assert finding.metadata["marker_platform"] == "UNIX"
    assert finding.metadata["confirmation"] == "REPEATED"
    assert finding.confidence.value == "HIGH"
    assert finding.cve_id is None and finding.cvss is None


def test_strong_windows_signature_produces_windows_family_finding() -> None:
    item = endpoint(server="Microsoft-IIS/10.0")
    client = FakeClient(lambda _url, _count: response(WINDOWS_MARKER))
    findings = asyncio.run(
        traversal_engine(client).analyze((discovery(item),))
    )
    assert len(client.calls) == 2
    assert findings[0].metadata["rule_family"] == "traversal-windows-canonical"
    assert findings[0].metadata["platform"] == "WINDOWS"
    assert (
        findings[0].metadata["confirmation_status"]
        == "CONFIRMED_BY_REPEAT"
    )
    assert findings[0].metadata["marker_platform"] == "WINDOWS"
    assert findings[0].metadata["inferred_platform"] == "WINDOWS"


def test_distinct_vulnerable_paths_are_not_deduplicated_by_parameter_name() -> None:
    unix = endpoint(server="nginx/1.24.0")
    windows = endpoint(
        "http://site.example/windows-download?file=manual.ini",
        server="Microsoft-IIS/10.0",
    )

    def handler(url: str, _count: int) -> WebResponse:
        if urlsplit(url).path == "/windows-download":
            return response(WINDOWS_MARKER)
        return response(UNIX_MARKER)

    client = FakeClient(handler)
    findings = asyncio.run(
        traversal_engine(client).analyze(
            (
                WebDiscoveryResult(
                    origin="http://site.example",
                    connect_host="203.0.113.10",
                    pages_crawled=2,
                    endpoints=(unix, windows),
                    started_at=NOW,
                    completed_at=NOW,
                ),
            )
        )
    )
    assert len(findings) == 2
    assert {finding.metadata["marker_platform"] for finding in findings} == {
        "UNIX",
        "WINDOWS",
    }


def test_baseline_marker_prevents_finding() -> None:
    item = endpoint(body=UNIX_MARKER)
    client = FakeClient(lambda _url, _count: response(UNIX_MARKER))
    findings = asyncio.run(
        traversal_engine(client).analyze((discovery(item),))
    )
    assert findings == ()


@pytest.mark.parametrize("status", [200, 404, 500])
def test_generic_status_responses_do_not_create_findings(status: int) -> None:
    client = FakeClient(
        lambda _url, _count: response("generic response", status=status)
    )
    findings = asyncio.run(
        traversal_engine(client).analyze((discovery(endpoint()),))
    )
    assert findings == ()


def test_length_change_random_jitter_and_safe_rejection_do_not_find() -> None:
    bodies = (
        "x" * 4_000,
        "random dynamic page " + "y" * 900,
        "encoded input safely rejected",
    )
    for body in bodies:
        client = FakeClient(lambda _url, _count, value=body: response(value))
        assert asyncio.run(
            traversal_engine(client).analyze((discovery(endpoint()),))
        ) == ()


def test_no_signal_stops_after_two_cross_platform_probes() -> None:
    client = FakeClient(lambda _url, _count: response())
    asyncio.run(traversal_engine(client, per_parameter=6).analyze((discovery(endpoint()),)))
    assert len(client.calls) == 2


def test_signal_escalates_and_traversal_sub_budget_never_exceeds_six() -> None:
    def handler(_url: str, count: int) -> WebResponse:
        if count <= 5:
            return response("different response", status=404)
        return response(UNIX_MARKER)

    client = FakeClient(handler)
    findings = asyncio.run(
        traversal_engine(client, per_parameter=6).analyze((discovery(endpoint()),))
    )
    assert findings == ()
    assert len(client.calls) <= 6


def test_adaptive_variant_marker_is_confirmed_with_six_request_cap() -> None:
    def handler(_url: str, count: int) -> WebResponse:
        if count < 5:
            return response("different response", status=404)
        return response(UNIX_MARKER)

    client = FakeClient(handler)
    findings = asyncio.run(
        traversal_engine(client, per_parameter=6).analyze((discovery(endpoint()),))
    )
    assert len(client.calls) == 6
    assert len(findings) == 1
    assert "adaptive variants" in findings[0].evidence[0].summary


def test_existing_global_per_parameter_budget_still_wins() -> None:
    client = FakeClient(
        lambda _url, _count: response("different response", status=404)
    )
    asyncio.run(traversal_engine(client, per_parameter=4).analyze((discovery(endpoint()),)))
    assert len(client.calls) == 4


def test_confirmation_failure_produces_no_high_confidence_finding() -> None:
    client = FakeClient(
        lambda _url, count: response(UNIX_MARKER if count == 1 else "normal")
    )
    findings = asyncio.run(
        traversal_engine(client).analyze((discovery(endpoint()),))
    )
    assert findings == ()


def test_get_form_file_input_is_eligible_but_post_form_is_not_submitted() -> None:
    root = endpoint("http://site.example/")
    get_form = WebForm(
        page_url=root.url,
        method="GET",
        action_url=root.url,
        inputs=(
            WebParameter(
                name="file",
                source=ParameterSource.FORM,
                input_type="text",
            ),
        ),
    )
    post_form = get_form.model_copy(update={"method": "POST"})
    client = FakeClient(lambda _url, _count: response(UNIX_MARKER))
    findings = asyncio.run(
        traversal_engine(client).analyze(
            (discovery(root, forms=(get_form, post_form)),)
        )
    )
    assert len(findings) == 1
    assert findings[0].metadata["parameter"] == "file"
    assert len(client.calls) == 2
