import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from rcscan.core.config import VerificationConfig
from rcscan.findings.models import (
    Finding,
    FindingType,
    Priority,
    RemediationGuidance,
    RemediationProvenance,
    Severity,
)
from rcscan.fingerprint.models import Confidence, Service
from rcscan.verification.base import stable_verification_id
from rcscan.verification.engine import VerificationEngine
from rcscan.verification.errors import VerificationBudgetExhausted
from rcscan.verification.http import VerificationHttpClient, _build_request
from rcscan.verification.models import (
    HttpExchange,
    HttpMethod,
    SafetyClassification,
    VerificationCheck,
    VerificationEvidence,
    VerificationResult,
    VerificationRule,
    VerificationStatus,
)
from rcscan.verification.registry import (
    APACHE_IDENTITY_RULE,
    DEMO_RULE,
    MICROSOFT_IIS_IDENTITY_RULE,
    NGINX_IDENTITY_RULE,
    PRODUCTION_RULES,
    HttpMarkerVerifier,
    HttpServerIdentityVerifier,
    VerificationRegistry,
    demo_registry,
    production_registry,
)
from rcscan.vuln.models import Applicability, LookupProvenance

NOW = datetime(2026, 1, 2, tzinfo=UTC)


def finding(
    index: int = 0,
    *,
    service: Service = Service.HTTP,
    product: str | None = "RCScanDemo",
    version: str | None = "1.0.0",
    cve_id: str | None = "CVE-DEMO-M6-0001",
    host: str = "127.0.0.1",
    port: int = 8080,
    finding_type: FindingType = FindingType.KNOWN_VULNERABILITY,
) -> Finding:
    return Finding(
        finding_id=f"AF-{index:024x}",
        title="Synthetic finding",
        type=finding_type,
        host=host,
        port=port,
        service=service,
        product=product,
        version=version,
        cve_id=cve_id,
        description="Synthetic deterministic finding.",
        evidence=(),
        applicability=Applicability.MATCH,
        confidence=Confidence.HIGH,
        confidence_reason="Synthetic test evidence.",
        severity=Severity.HIGH,
        priority=Priority.HIGH,
        remediation=RemediationGuidance(
            text="Apply the synthetic update.",
            provenance=RemediationProvenance.GENERIC,
            source="test",
        ),
        source="test",
        provider_provenance=LookupProvenance.SYNTHETIC,
        first_observed=NOW,
    )


def rule(**updates: Any) -> VerificationRule:
    values = DEMO_RULE.model_dump()
    values.update(updates)
    return VerificationRule.model_validate(values)


def result_for(
    item: Finding,
    *,
    status: VerificationStatus = VerificationStatus.VERIFIED,
    requests: int = 0,
) -> VerificationResult:
    return VerificationResult(
        finding_id=item.finding_id,
        verification_id=stable_verification_id(item.finding_id, "test", "test-rule"),
        verifier_name="test",
        rule_id="test-rule",
        status=status,
        confidence=Confidence.HIGH,
        reason="Synthetic result.",
        requests_attempted=requests,
        duration_ms=0,
        generated_at=NOW,
    )


class Session:
    def __init__(self, exchange: object) -> None:
        self.exchange = exchange
        self.calls = 0

    async def request(self, _finding: Finding, _rule: VerificationRule) -> object:
        self.calls += 1
        if isinstance(self.exchange, BaseException):
            raise self.exchange
        return self.exchange


@pytest.mark.parametrize(
    ("field", "bad_values"),
    [
        ("max_requests_per_finding", (0, 11)),
        ("max_total_requests", (0, 101)),
        ("timeout_seconds", (0, 10.01)),
        ("max_response_bytes", (1_023, 65_537)),
        ("concurrency", (0, 11)),
    ],
)
def test_verification_config_enforces_lower_and_upper_bounds(
    field: str, bad_values: tuple[int | float, ...]
) -> None:
    for value in bad_values:
        with pytest.raises(ValidationError):
            VerificationConfig(**{field: value})


def test_verification_models_enforce_request_evidence_and_result_bounds() -> None:
    with pytest.raises(ValidationError):
        VerificationEvidence(summary="")
    with pytest.raises(ValidationError):
        rule(max_requests=3)
    with pytest.raises(ValidationError):
        rule(timeout_seconds=5.01)
    with pytest.raises(ValidationError):
        values = result_for(finding()).model_dump()
        values["requests_attempted"] = 3
        VerificationResult.model_validate(values)


def test_rules_allow_only_reviewed_read_only_methods_and_safe_absolute_paths() -> None:
    assert set(HttpMethod) == {HttpMethod.HEAD, HttpMethod.GET, HttpMethod.OPTIONS}
    assert set(SafetyClassification) == {
        SafetyClassification.SYNTHETIC_READ_ONLY,
        SafetyClassification.PRODUCTION_READ_ONLY_IDENTITY,
    }
    for unsafe_path in ("relative", "/ok\r\nCookie: secret"):
        with pytest.raises(ValidationError):
            rule(path=unsafe_path)
    values = DEMO_RULE.model_dump()
    values["method"] = "POST"
    with pytest.raises(ValidationError):
        VerificationRule.model_validate(values)


def test_rule_model_rejects_incompatible_identity_actions_and_markers() -> None:
    values = NGINX_IDENTITY_RULE.model_dump()
    values["method"] = HttpMethod.GET
    with pytest.raises(ValidationError):
        VerificationRule.model_validate(values)

    values = NGINX_IDENTITY_RULE.model_dump()
    values["expected_marker"] = "unreviewed"
    with pytest.raises(ValidationError):
        VerificationRule.model_validate(values)

    values = DEMO_RULE.model_dump()
    values["expected_marker"] = None
    with pytest.raises(ValidationError):
        VerificationRule.model_validate(values)


def test_stable_verification_id_is_repeatable_case_insensitive_and_distinct() -> None:
    first = stable_verification_id("AF-" + "a" * 24, "Verifier", "Rule-ID")
    assert first == stable_verification_id("af-" + "A" * 24, "verifier", "rule-id")
    assert first != stable_verification_id("AF-" + "b" * 24, "Verifier", "Rule-ID")
    assert first.startswith("AV-")
    assert len(first) == 27


def test_default_registry_supports_only_the_exact_reviewed_demo_identity() -> None:
    registry = demo_registry()
    assert registry.select(finding()) is not None

    mismatches = (
        finding(service=Service.HTTPS),
        finding(product="ArbitraryProduct"),
        finding(version="9.9.9"),
        finding(cve_id="CVE-DEMO-OTHER"),
        finding(service=Service.UNKNOWN),
        finding(version=None),
    )
    assert all(registry.select(item) is None for item in mismatches)


@pytest.mark.parametrize(
    ("rule", "product"),
    [
        (NGINX_IDENTITY_RULE, "nginx"),
        (APACHE_IDENTITY_RULE, "Apache"),
        (MICROSOFT_IIS_IDENTITY_RULE, "Microsoft-IIS"),
    ],
)
@pytest.mark.parametrize("service", [Service.HTTP, Service.HTTPS])
@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "10.20.30.40", "203.0.113.9", "authorized.example.test"],
)
def test_production_rules_are_target_agnostic(
    rule: VerificationRule,
    product: str,
    service: Service,
    host: str,
) -> None:
    item = finding(
        service=service,
        product=product,
        version="1.2.3",
        cve_id="CVE-2024-1234",
        host=host,
    )
    selected = production_registry().select(item)
    assert selected is not None
    assert selected.rule_id == rule.rule_id


def test_production_rules_contain_no_target_specific_criteria() -> None:
    serialized = repr(tuple(rule.model_dump() for rule in PRODUCTION_RULES)).casefold()
    assert "localhost" not in serialized
    assert "127.0.0.1" not in serialized
    assert "private" not in serialized
    assert all(rule.services == (Service.HTTP, Service.HTTPS) for rule in PRODUCTION_RULES)
    assert all(rule.check is VerificationCheck.SERVER_IDENTITY for rule in PRODUCTION_RULES)


@pytest.mark.parametrize(
    "item",
    [
        finding(product="Caddy", version="2.8.4", cve_id="CVE-2024-1234"),
        finding(product="nginx", version=None, cve_id="CVE-2024-1234"),
        finding(product="nginx", version="1.2.3", cve_id=None),
        finding(
            product="nginx",
            version="1.2.3",
            cve_id="CVE-2024-1234",
            finding_type=FindingType.MISCONFIGURATION,
        ),
    ],
)
def test_production_registry_strictly_skips_unsupported_evidence(item: Finding) -> None:
    assert production_registry().select(item) is None


@pytest.mark.parametrize(
    ("exchange", "expected_status", "expected_confidence"),
    [
        (
            HttpExchange(
                status_code=200,
                body=b"prefix RCSCAN_M6_DEMO_OK suffix",
                duration_ms=1,
            ),
            VerificationStatus.VERIFIED,
            Confidence.HIGH,
        ),
        (
            HttpExchange(status_code=200, body=b"marker absent", duration_ms=1),
            VerificationStatus.NOT_VERIFIED,
            Confidence.MEDIUM,
        ),
        (
            HttpExchange(error="TimeoutError", duration_ms=1),
            VerificationStatus.INCONCLUSIVE,
            Confidence.LOW,
        ),
        (
            HttpExchange(body=b"x", truncated=True, duration_ms=1),
            VerificationStatus.INCONCLUSIVE,
            Confidence.LOW,
        ),
        (
            HttpExchange(body=b"x", malformed=True, duration_ms=1),
            VerificationStatus.INCONCLUSIVE,
            Confidence.LOW,
        ),
        (
            HttpExchange(status_code=302, duration_ms=1),
            VerificationStatus.INCONCLUSIVE,
            Confidence.LOW,
        ),
    ],
)
def test_demo_verifier_maps_every_exchange_outcome(
    exchange: HttpExchange,
    expected_status: VerificationStatus,
    expected_confidence: Confidence,
) -> None:
    session = Session(exchange)
    result = asyncio.run(HttpMarkerVerifier(DEMO_RULE).verify(session, finding()))

    assert result.status is expected_status
    assert result.confidence is expected_confidence
    assert result.requests_attempted == 1
    assert session.calls == 1


def test_demo_verifier_budget_exhaustion_is_not_attempted() -> None:
    result = asyncio.run(
        HttpMarkerVerifier(DEMO_RULE).verify(
            Session(VerificationBudgetExhausted()),
            finding(),
        )
    )
    assert result.status is VerificationStatus.NOT_ATTEMPTED
    assert result.requests_attempted == 0


@pytest.mark.parametrize(
    ("server", "status"),
    [
        ("nginx/1.24.0", VerificationStatus.VERIFIED),
        ("nginx/1.24.1", VerificationStatus.NOT_VERIFIED),
        ("Apache/1.24.0", VerificationStatus.NOT_VERIFIED),
        ("nginx", VerificationStatus.NOT_VERIFIED),
        (None, VerificationStatus.NOT_VERIFIED),
    ],
)
def test_production_identity_verifier_requires_exact_product_and_version(
    server: str | None,
    status: VerificationStatus,
) -> None:
    headers = {} if server is None else {"server": server}
    item = finding(
        product="nginx",
        version="1.24.0",
        cve_id="CVE-2024-1234",
    )
    result = asyncio.run(
        HttpServerIdentityVerifier(NGINX_IDENTITY_RULE).verify(
            Session(HttpExchange(status_code=200, headers=headers, duration_ms=1)),
            item,
        )
    )
    assert result.status is status
    assert result.requests_attempted == 1
    assert "exploitability" in result.reason or status is VerificationStatus.NOT_VERIFIED


@pytest.mark.parametrize(
    "exchange",
    [
        HttpExchange(error="TimeoutError", duration_ms=1),
        HttpExchange(body=b"x", truncated=True, duration_ms=1),
        HttpExchange(body=b"x", malformed=True, duration_ms=1),
        HttpExchange(status_code=302, duration_ms=1),
    ],
)
def test_production_identity_verifier_preserves_inconclusive_failures(
    exchange: HttpExchange,
) -> None:
    item = finding(product="nginx", version="1.24.0", cve_id="CVE-2024-1234")
    result = asyncio.run(
        HttpServerIdentityVerifier(NGINX_IDENTITY_RULE).verify(Session(exchange), item)
    )
    assert result.status is VerificationStatus.INCONCLUSIVE


def test_production_identity_budget_exhaustion_is_not_attempted() -> None:
    item = finding(product="nginx", version="1.24.0", cve_id="CVE-2024-1234")
    result = asyncio.run(
        HttpServerIdentityVerifier(NGINX_IDENTITY_RULE).verify(
            Session(VerificationBudgetExhausted()),
            item,
        )
    )
    assert result.status is VerificationStatus.NOT_ATTEMPTED
    assert result.requests_attempted == 0


class RaisingVerifier:
    name = "raising"
    rule_id = "raising-rule"

    def supports(self, _finding: Finding) -> bool:
        return True

    async def verify(self, _session: object, _finding: Finding) -> VerificationResult:
        raise RuntimeError("isolated")


class InvalidExchangeVerifier(HttpMarkerVerifier):
    def supports(self, _finding: Finding) -> bool:
        return True


class CountingClient:
    def __init__(self, exchange: object | None = None) -> None:
        self.calls = 0
        self.exchange = exchange or HttpExchange(status_code=200, duration_ms=0)

    async def request(self, _finding: Finding, _rule: VerificationRule) -> object:
        self.calls += 1
        return self.exchange


def engine(
    *,
    registry: VerificationRegistry | None = None,
    client: object | None = None,
    per_finding: int = 2,
    total: int = 20,
    concurrency: int = 2,
) -> VerificationEngine:
    return VerificationEngine(
        timeout_seconds=1,
        max_response_bytes=1_024,
        max_requests_per_finding=per_finding,
        max_total_requests=total,
        concurrency=concurrency,
        registry=registry,
        client=client,
    )


def test_engine_reports_skipped_unsupported_and_error_exception() -> None:
    skipped = asyncio.run(engine().verify((finding(product="other"),)))[0]
    errored = asyncio.run(
        engine(registry=VerificationRegistry((RaisingVerifier(),))).verify((finding(),))
    )[0]

    assert skipped.status is VerificationStatus.SKIPPED
    assert skipped.requests_attempted == 0
    assert errored.status is VerificationStatus.ERROR
    assert errored.requests_attempted == 0


def test_malformed_session_value_is_isolated_as_error() -> None:
    client = CountingClient(exchange=object())
    verifier = InvalidExchangeVerifier(DEMO_RULE)
    result = asyncio.run(
        engine(
            registry=VerificationRegistry((verifier,)),
            client=client,
        ).verify((finding(),))
    )[0]
    assert result.status is VerificationStatus.ERROR
    assert result.requests_attempted == 1


def test_empty_findings_make_zero_client_calls() -> None:
    client = CountingClient()
    assert asyncio.run(engine(client=client).verify(())) == ()
    assert client.calls == 0


def test_unsupported_production_finding_is_skipped_without_request() -> None:
    client = CountingClient()
    result = asyncio.run(
        engine(registry=production_registry(), client=client).verify(
            (
                finding(
                    product="Caddy",
                    version="2.8.4",
                    cve_id="CVE-2024-1234",
                    host="arbitrary.example.test",
                ),
            )
        )
    )[0]
    assert result.status is VerificationStatus.SKIPPED
    assert result.requests_attempted == 0
    assert client.calls == 0


def test_production_identity_rules_remain_under_central_total_budget() -> None:
    client = CountingClient(
        HttpExchange(
            status_code=200,
            headers={"server": "nginx/1.24.0"},
            duration_ms=0,
        )
    )
    items = tuple(
        finding(
            index,
            product="nginx",
            version="1.24.0",
            cve_id=f"CVE-2024-12{index:02d}",
            host=f"host-{index}.example.test",
        )
        for index in range(2)
    )
    results = asyncio.run(
        engine(
            registry=production_registry(),
            client=client,
            total=1,
            concurrency=1,
        ).verify(items)
    )
    assert client.calls == 1
    assert [result.status for result in results] == [
        VerificationStatus.VERIFIED,
        VerificationStatus.NOT_ATTEMPTED,
    ]


def test_total_budget_is_hard_and_yields_not_attempted() -> None:
    client = CountingClient()
    results = asyncio.run(
        engine(client=client, total=1, concurrency=1).verify((finding(), finding(1)))
    )
    assert client.calls == 1
    assert [item.status for item in results] == [
        VerificationStatus.NOT_VERIFIED,
        VerificationStatus.NOT_ATTEMPTED,
    ]
    assert [item.requests_attempted for item in results] == [1, 0]


class MultiRequestVerifier:
    name = "multi"
    rule_id = "multi-rule"

    def __init__(self, request_count: int) -> None:
        self.request_count = request_count

    def supports(self, _finding: Finding) -> bool:
        return True

    async def verify(self, session: object, item: Finding) -> VerificationResult:
        for _ in range(self.request_count):
            await session.request(item, rule(max_requests=2))
        return result_for(item, requests=min(self.request_count, 2))


class OneErrorVerifier:
    name = "one-error"
    rule_id = "one-error-rule"

    def supports(self, _finding: Finding) -> bool:
        return True

    async def verify(self, _session: object, item: Finding) -> VerificationResult:
        if item.finding_id == finding().finding_id:
            raise RuntimeError("first only")
        return result_for(item)


def test_multiple_findings_continue_after_one_verifier_error() -> None:
    results = asyncio.run(
        engine(
            registry=VerificationRegistry((OneErrorVerifier(),)),
            concurrency=1,
        ).verify((finding(), finding(1), finding(2)))
    )
    assert [item.status for item in results] == [
        VerificationStatus.ERROR,
        VerificationStatus.VERIFIED,
        VerificationStatus.VERIFIED,
    ]


def test_per_finding_budget_blocks_malicious_multi_request_verifier() -> None:
    client = CountingClient()
    verifier = MultiRequestVerifier(request_count=50)
    result = asyncio.run(
        engine(
            registry=VerificationRegistry((verifier,)),
            client=client,
            per_finding=2,
            total=100,
        ).verify((finding(),))
    )[0]
    assert client.calls == 2
    assert result.status is VerificationStatus.ERROR
    assert result.requests_attempted == 2


def test_total_budget_remains_hard_across_multi_request_verifiers() -> None:
    client = CountingClient()
    verifier = MultiRequestVerifier(request_count=2)
    results = asyncio.run(
        engine(
            registry=VerificationRegistry((verifier,)),
            client=client,
            per_finding=2,
            total=3,
            concurrency=1,
        ).verify((finding(), finding(1)))
    )
    assert client.calls == 3
    assert results[0].status is VerificationStatus.VERIFIED
    assert results[1].status is VerificationStatus.ERROR
    assert results[1].requests_attempted == 1


class BlockingClient:
    def __init__(self, release: asyncio.Event) -> None:
        self.release = release
        self.active = 0
        self.peak = 0
        self.started = asyncio.Event()

    async def request(self, _finding: Finding, _rule: VerificationRule) -> HttpExchange:
        self.active += 1
        self.peak = max(self.peak, self.active)
        if self.peak >= 2:
            self.started.set()
        try:
            await self.release.wait()
            return HttpExchange(status_code=200, duration_ms=0)
        finally:
            self.active -= 1


def test_concurrency_is_capped_and_fixed_workers_process_all_findings() -> None:
    async def scenario() -> tuple[tuple[VerificationResult, ...], int]:
        release = asyncio.Event()
        client = BlockingClient(release)
        task = asyncio.create_task(
            engine(client=client, concurrency=2).verify(tuple(finding(i) for i in range(5)))
        )
        await asyncio.wait_for(client.started.wait(), timeout=1)
        assert client.active == 2
        release.set()
        return await task, client.peak

    results, peak = asyncio.run(scenario())
    assert len(results) == 5
    assert peak == 2


class FakeWriter:
    def __init__(self) -> None:
        self.payload = b""
        self.closed = False
        self.waited = False

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


def test_http_request_is_minimal_and_contains_no_credentials_or_cookies() -> None:
    payload = _build_request("demo.local", DEMO_RULE)
    assert payload.startswith(b"GET /rcscan-demo-status HTTP/1.1\r\n")
    assert b"Authorization:" not in payload
    assert b"Cookie:" not in payload
    assert b"Accept: text/plain\r\n" in payload


def test_plain_transport_caps_response_and_closes_writer() -> None:
    writer = FakeWriter()

    async def connect(_host: str, _port: int) -> tuple[asyncio.StreamReader, Any]:
        return reader_with(b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 2_000), writer

    client = VerificationHttpClient(
        timeout_seconds=1,
        max_response_bytes=1_024,
        plain_connector=connect,
    )
    exchange = asyncio.run(client.request(finding(), DEMO_RULE))
    assert exchange.truncated
    assert len(exchange.body) == 1_024
    assert writer.closed and writer.waited
    assert writer.payload.count(b"\r\n\r\n") == 1


def test_redirect_is_returned_without_second_connection() -> None:
    writer = FakeWriter()
    calls = 0

    async def connect(_host: str, _port: int) -> tuple[asyncio.StreamReader, Any]:
        nonlocal calls
        calls += 1
        return (
            reader_with(
                b"HTTP/1.1 302 Found\r\nLocation: http://elsewhere.test/\r\n\r\n"
            ),
            writer,
        )

    exchange = asyncio.run(
        VerificationHttpClient(
            timeout_seconds=1,
            max_response_bytes=1_024,
            plain_connector=connect,
        ).request(finding(), DEMO_RULE)
    )
    assert exchange.status_code == 302
    assert calls == 1


def test_https_uses_only_tls_connector_with_bounded_tls_options() -> None:
    plain_calls = 0
    tls_calls: list[dict[str, object]] = []
    writer = FakeWriter()

    async def plain(_host: str, _port: int) -> tuple[asyncio.StreamReader, Any]:
        nonlocal plain_calls
        plain_calls += 1
        raise AssertionError("plain connector used")

    async def tls(
        host: str,
        port: int,
        **kwargs: object,
    ) -> tuple[asyncio.StreamReader, Any]:
        tls_calls.append({"host": host, "port": port, **kwargs})
        return reader_with(b"HTTP/1.1 200 OK\r\n\r\nok"), writer

    exchange = asyncio.run(
        VerificationHttpClient(
            timeout_seconds=1,
            max_response_bytes=1_024,
            plain_connector=plain,
            tls_connector=tls,
        ).request(
            finding(service=Service.HTTPS, host="demo.test", port=443),
            rule(services=(Service.HTTPS,)),
        )
    )
    assert exchange.status_code == 200
    assert plain_calls == 0
    assert tls_calls[0]["server_hostname"] == "demo.test"
    assert tls_calls[0]["ssl_handshake_timeout"] == 1


def test_production_head_request_is_minimal_and_read_only() -> None:
    payload = _build_request("authorized.example.test", NGINX_IDENTITY_RULE)
    assert payload.startswith(b"HEAD / HTTP/1.1\r\n")
    assert b"Authorization:" not in payload
    assert b"Cookie:" not in payload
    assert b"\r\n\r\n" in payload


def test_timeout_is_inconclusive_and_writer_cleanup_completes() -> None:
    async def scenario() -> tuple[HttpExchange, FakeWriter]:
        writer = FakeWriter()
        reader = asyncio.StreamReader()

        async def connect(_host: str, _port: int) -> tuple[asyncio.StreamReader, Any]:
            return reader, writer

        exchange = await VerificationHttpClient(
            timeout_seconds=0.01,
            max_response_bytes=1_024,
            plain_connector=connect,
        ).request(finding(), rule(timeout_seconds=0.01))
        return exchange, writer

    exchange, writer = asyncio.run(scenario())
    assert exchange.error is not None and "TimeoutError" in exchange.error
    assert writer.closed and writer.waited


def test_cancellation_propagates_after_writer_cleanup() -> None:
    async def scenario() -> FakeWriter:
        writer = FakeWriter()
        reader = asyncio.StreamReader()

        async def connect(_host: str, _port: int) -> tuple[asyncio.StreamReader, Any]:
            return reader, writer

        task = asyncio.create_task(
            VerificationHttpClient(
                timeout_seconds=5,
                max_response_bytes=1_024,
                plain_connector=connect,
            ).request(finding(), DEMO_RULE)
        )
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return writer

    writer = asyncio.run(scenario())
    assert writer.closed and writer.waited
