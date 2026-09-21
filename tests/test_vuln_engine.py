import asyncio
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from rcscan.fingerprint.models import Confidence, Service, ServiceFingerprint
from rcscan.network.models import (
    DiscoveryMethod,
    DiscoveryStatus,
    HostScanResult,
    PortResult,
    PortState,
)
from rcscan.vuln.cache import VulnerabilityCache
from rcscan.vuln.engine import VulnerabilityEngine, correlate_identity
from rcscan.vuln.errors import ProviderUnavailableError
from rcscan.vuln.models import (
    AffectedRange,
    Applicability,
    CVSSMetric,
    LookupProvenance,
    NormalizedIdentity,
    ProviderQueryResult,
    VulnerabilityRecord,
)

NOW = datetime(2026, 1, 2, tzinfo=UTC)


def identity(
    version: str = "1.10", confidence: Confidence = Confidence.HIGH
) -> NormalizedIdentity:
    return NormalizedIdentity(
        original_product="nginx",
        vendor="nginx",
        product="nginx",
        version=version,
        cpe23=f"cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
        confidence=confidence,
        reason="synthetic evidence",
    )


def record(
    cve_id: str = "CVE-2026-1000",
    *,
    affected: tuple[AffectedRange, ...] | None = None,
    cvss: tuple[CVSSMetric, ...] = (),
    description: str = "description",
    references: tuple[str, ...] = (),
) -> VulnerabilityRecord:
    return VulnerabilityRecord(
        cve_id=cve_id,
        source="nvd",
        description=description,
        cvss=cvss,
        references=references,
        affected=affected
        if affected is not None
        else (AffectedRange(vendor="nginx", product="nginx", version="1.10"),),
    )


def query(*records: VulnerabilityRecord) -> ProviderQueryResult:
    return ProviderQueryResult(
        provider="nvd",
        identity_key=identity().cache_key,
        records=records,
        lookup_at=NOW,
        provenance=LookupProvenance.SYNTHETIC,
    )


def test_correlation_match_has_explicit_reason_and_separate_confidence() -> None:
    metric = CVSSMetric(version="3.1", base_score=9.8, base_severity="CRITICAL")
    candidate = correlate_identity(identity(), query(record(cvss=(metric,))), 10)[0]

    assert candidate.affected_match is Applicability.MATCH
    assert candidate.environment_applicability is Applicability.MATCH
    assert candidate.match_confidence is Confidence.HIGH
    assert candidate.match_reason == "Observed version matches a published affected version range."
    assert candidate.cvss == metric
    assert candidate.cvss.base_score != candidate.match_confidence
    assert candidate.status.value == "POTENTIAL_MATCH"


def test_conditional_match_is_environment_indeterminate_and_medium_confidence() -> None:
    conditional = AffectedRange(
        vendor="nginx",
        product="nginx",
        version="1.10",
        conditions_unverified=True,
    )
    candidate = correlate_identity(identity(), query(record(affected=(conditional,))), 10)[0]

    assert candidate.affected_match is Applicability.MATCH
    assert candidate.environment_applicability is Applicability.INDETERMINATE
    assert candidate.match_confidence is Confidence.MEDIUM
    assert "environment conditions were not verified" in candidate.match_reason


def test_low_fingerprint_confidence_caps_candidate_at_medium() -> None:
    candidate = correlate_identity(
        identity(confidence=Confidence.LOW), query(record()), 10
    )[0]
    assert candidate.match_confidence is Confidence.MEDIUM


def test_malformed_range_produces_indeterminate_candidate() -> None:
    malformed = AffectedRange(
        vendor="nginx", product="nginx", version_start_including="bad"
    )
    candidate = correlate_identity(identity(), query(record(affected=(malformed,))), 10)[0]
    assert candidate.affected_match is Applicability.INDETERMINATE
    assert candidate.environment_applicability is Applicability.INDETERMINATE
    assert candidate.match_confidence is Confidence.LOW
    assert "not safely comparable" in candidate.match_reason


@pytest.mark.parametrize(
    "affected",
    [
        (AffectedRange(vendor="nginx", product="nginx", version="1.9"),),
        (AffectedRange(vendor="apache", product="http_server", version="1.10"),),
        (),
    ],
)
def test_no_match_records_are_omitted(affected: tuple[AffectedRange, ...]) -> None:
    assert correlate_identity(identity(), query(record(affected=affected)), 10) == ()


def test_duplicate_cves_and_candidate_limit_are_deterministic() -> None:
    records = (
        record("CVE-2026-1000"),
        record("CVE-2026-1000", description="duplicate"),
        record("CVE-2026-1001"),
        record("CVE-2026-1002"),
    )
    candidates = correlate_identity(identity(), query(*records), 2)
    assert [item.cve_id for item in candidates] == ["CVE-2026-1000", "CVE-2026-1001"]


def test_highest_cvss_version_is_preferred_not_highest_score() -> None:
    metrics = (
        CVSSMetric(version="2.0", base_score=10),
        CVSSMetric(version="3.1", base_score=4),
        CVSSMetric(version="4.0", base_score=1),
    )
    assert correlate_identity(identity(), query(record(cvss=metrics)), 10)[0].cvss == metrics[2]


def test_missing_description_references_and_cvss_are_preserved_safely() -> None:
    candidate = correlate_identity(
        identity(),
        query(record(description="No description supplied.", references=(), cvss=())),
        10,
    )[0]
    assert candidate.description == "No description supplied."
    assert candidate.references == ()
    assert candidate.cvss is None


def fingerprint(
    product: str | None = "nginx", version: str | None = "1.10"
) -> ServiceFingerprint:
    return ServiceFingerprint(
        service=Service.HTTP,
        product=product,
        version=version,
        confidence=Confidence.HIGH,
        evidence=(),
        probe_used="synthetic",
    )


def port(
    number: int,
    *,
    state: PortState = PortState.OPEN,
    fp: ServiceFingerprint | None = None,
) -> PortResult:
    return PortResult(
        host="10.0.0.1",
        port=number,
        state=state,
        latency_ms=1,
        timestamp=NOW,
        fingerprint=fp,
    )


def host(*ports: PortResult) -> HostScanResult:
    return HostScanResult(
        target="10.0.0.1",
        resolved_address="10.0.0.1",
        discovery_status=DiscoveryStatus.REACHABLE,
        discovery_method=DiscoveryMethod.TCP_CONNECT,
        discovery_latency_ms=1,
        ports=ports,
        started_at=NOW,
        completed_at=NOW,
    )


def engine(provider: AsyncMock, *, max_requests: int = 25) -> VulnerabilityEngine:
    provider.name = "nvd"
    provider.search_product.return_value = query(record())
    return VulnerabilityEngine(
        provider,
        cache=None,
        max_provider_requests=max_requests,
        max_candidates_per_identity=10,
    )


def test_duplicate_fingerprints_make_one_provider_request_and_enrich_both() -> None:
    provider = AsyncMock()
    result = asyncio.run(
        engine(provider).enrich_hosts(
            (host(port(80, fp=fingerprint()), port(8080, fp=fingerprint())),)
        )
    )
    provider.search_product.assert_awaited_once()
    assert all(item.vulnerability_candidates for item in result[0].ports)


def test_cache_hit_makes_zero_provider_requests(tmp_path: Path) -> None:
    provider = AsyncMock()
    provider.name = "nvd"
    stored = query(record())
    vulnerability_cache = VulnerabilityCache(
        tmp_path / "cache.json", ttl_hours=24, max_entries=10
    )
    vulnerability_cache.set(stored)
    cached_engine = VulnerabilityEngine(
        provider,
        cache=vulnerability_cache,
        max_provider_requests=10,
        max_candidates_per_identity=10,
    )

    result = asyncio.run(
        cached_engine.enrich_hosts((host(port(80, fp=fingerprint())),))
    )

    provider.search_product.assert_not_awaited()
    assert result[0].ports[0].vulnerability_candidates[0].provenance is (
        LookupProvenance.CACHE
    )


def test_provider_failure_is_attached_without_losing_port() -> None:
    provider = AsyncMock()
    provider.name = "nvd"
    provider.search_product.side_effect = ProviderUnavailableError("provider unavailable")
    result = asyncio.run(engine(provider).enrich_hosts((host(port(80, fp=fingerprint())),)))
    enriched = result[0].ports[0]
    assert enriched.vulnerability_candidates == ()
    assert enriched.vulnerability_lookup_error == "provider unavailable"


@pytest.mark.parametrize(
    "item",
    [
        port(80, state=PortState.CLOSED, fp=fingerprint()),
        port(80, state=PortState.OPEN, fp=None),
        port(80, state=PortState.OPEN, fp=fingerprint(None, "1.10")),
        port(80, state=PortState.OPEN, fp=fingerprint("nginx", None)),
        port(80, state=PortState.OPEN, fp=fingerprint("custom", "1.10")),
    ],
)
def test_ineligible_ports_make_zero_provider_requests(item: PortResult) -> None:
    provider = AsyncMock()
    result = asyncio.run(engine(provider).enrich_hosts((host(item),)))
    provider.search_product.assert_not_awaited()
    assert result[0].ports[0] == item


def test_provider_request_bound_marks_remaining_identity_unavailable() -> None:
    provider = AsyncMock()
    first = port(80, fp=fingerprint("nginx", "1.10"))
    second = port(81, fp=fingerprint("nginx", "1.11"))
    result = asyncio.run(engine(provider, max_requests=1).enrich_hosts((host(first, second),)))
    provider.search_product.assert_awaited_once()
    assert result[0].ports[1].vulnerability_lookup_error == (
        "Provider request limit reached for this scan."
    )
