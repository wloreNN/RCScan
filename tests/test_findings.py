from datetime import UTC, datetime

import pytest

from rcscan.findings.engine import FindingEngine
from rcscan.findings.models import (
    EvidenceType,
    Priority,
    RemediationProvenance,
    Severity,
)
from rcscan.findings.policy import (
    bounded_references,
    priority_for,
    severity_from_cvss,
)
from rcscan.fingerprint.models import Confidence, Service, ServiceFingerprint
from rcscan.network.models import (
    DiscoveryMethod,
    DiscoveryStatus,
    HostScanResult,
    PortResult,
    PortState,
)
from rcscan.vuln.models import (
    Applicability,
    CVSSMetric,
    LookupProvenance,
    VulnerabilityCandidate,
)

NOW = datetime(2026, 1, 2, tzinfo=UTC)


def fingerprint(
    *,
    service: Service = Service.HTTP,
    product: str | None = "nginx",
    version: str | None = "1.10",
) -> ServiceFingerprint:
    return ServiceFingerprint(
        service=service,
        product=product,
        version=version,
        confidence=Confidence.HIGH,
        evidence=(),
        probe_used="synthetic",
    )


def candidate(
    cve_id: str = "CVE-2026-1000",
    *,
    affected: Applicability = Applicability.MATCH,
    environment: Applicability = Applicability.MATCH,
    confidence: Confidence = Confidence.HIGH,
    cvss: CVSSMetric | None = None,
    references: tuple[str, ...] = (),
    metadata: dict[str, str] | None = None,
) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        cve_id=cve_id,
        source="nvd",
        description=f"Potential issue described by {cve_id}.",
        cvss=cvss,
        references=references,
        affected_match=affected,
        environment_applicability=environment,
        match_confidence=confidence,
        match_reason="Synthetic deterministic correlation evidence.",
        fingerprint_evidence_reference="nginx 1.10",
        lookup_at=NOW,
        provenance=LookupProvenance.SYNTHETIC,
        metadata=metadata or {},
    )


def port(
    number: int = 80,
    *,
    fp: ServiceFingerprint | None = None,
    candidates: tuple[object, ...] = (),
    state: PortState = PortState.OPEN,
) -> PortResult:
    result = PortResult(
        host="10.0.0.1",
        port=number,
        state=state,
        latency_ms=1,
        timestamp=NOW,
        fingerprint=fp,
    )
    return result.model_copy(update={"vulnerability_candidates": candidates})


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


def generate(*ports: PortResult):
    return FindingEngine().generate((host(*ports),))


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Severity.INFORMATIONAL),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_severity_uses_cvss_base_score_boundaries(
    score: float, expected: Severity
) -> None:
    metric = CVSSMetric(version="3.1", base_score=score)

    assert severity_from_cvss(metric) is expected


def test_severity_supports_cvss_3x_and_missing_metric() -> None:
    assert severity_from_cvss(CVSSMetric(version="3.0", base_score=7.5)) is Severity.HIGH
    assert severity_from_cvss(CVSSMetric(version="3.1", base_score=9.8)) is Severity.CRITICAL
    assert severity_from_cvss(None) is Severity.UNKNOWN


@pytest.mark.parametrize(
    ("severity", "applicability", "confidence", "expected"),
    [
        (Severity.CRITICAL, Applicability.MATCH, Confidence.HIGH, Priority.CRITICAL),
        (Severity.HIGH, Applicability.MATCH, Confidence.HIGH, Priority.HIGH),
        (Severity.MEDIUM, Applicability.MATCH, Confidence.HIGH, Priority.MEDIUM),
        (Severity.LOW, Applicability.MATCH, Confidence.HIGH, Priority.LOW),
        (
            Severity.INFORMATIONAL,
            Applicability.MATCH,
            Confidence.HIGH,
            Priority.INFORMATIONAL,
        ),
        (Severity.CRITICAL, Applicability.MATCH, Confidence.MEDIUM, Priority.HIGH),
        (Severity.HIGH, Applicability.MATCH, Confidence.MEDIUM, Priority.MEDIUM),
        (
            Severity.CRITICAL,
            Applicability.INDETERMINATE,
            Confidence.HIGH,
            Priority.HIGH,
        ),
        (
            Severity.HIGH,
            Applicability.INDETERMINATE,
            Confidence.MEDIUM,
            Priority.MEDIUM,
        ),
        (Severity.CRITICAL, Applicability.MATCH, Confidence.LOW, Priority.MEDIUM),
        (Severity.HIGH, Applicability.MATCH, Confidence.LOW, Priority.LOW),
        (
            Severity.LOW,
            Applicability.INDETERMINATE,
            Confidence.LOW,
            Priority.INFORMATIONAL,
        ),
        (Severity.UNKNOWN, Applicability.MATCH, Confidence.HIGH, Priority.INFORMATIONAL),
        (
            Severity.CRITICAL,
            Applicability.NO_MATCH,
            Confidence.HIGH,
            Priority.INFORMATIONAL,
        ),
    ],
)
def test_priority_policy_is_exact(
    severity: Severity,
    applicability: Applicability,
    confidence: Confidence,
    expected: Priority,
) -> None:
    assert priority_for(severity, applicability, confidence) is expected


def test_high_confidence_match_creates_explainable_finding() -> None:
    metric = CVSSMetric(version="3.1", base_score=9.8, base_severity="CRITICAL")

    findings = generate(port(fp=fingerprint(), candidates=(candidate(cvss=metric),)))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.cve_id == "CVE-2026-1000"
    assert finding.applicability is Applicability.MATCH
    assert finding.confidence is Confidence.HIGH
    assert finding.severity is Severity.CRITICAL
    assert finding.priority is Priority.CRITICAL
    assert finding.provider_provenance is LookupProvenance.SYNTHETIC
    assert [item.type for item in finding.evidence] == [
        EvidenceType.OBSERVED,
        EvidenceType.NORMALIZED,
        EvidenceType.CORRELATION,
    ]
    assert "HIGH because" in finding.confidence_reason


def test_environmental_indeterminate_reduces_priority() -> None:
    item = candidate(
        environment=Applicability.INDETERMINATE,
        confidence=Confidence.MEDIUM,
        cvss=CVSSMetric(version="3.1", base_score=9.8),
    )

    finding = generate(port(fp=fingerprint(), candidates=(item,)))[0]

    assert finding.applicability is Applicability.INDETERMINATE
    assert finding.priority is Priority.HIGH
    assert "conditions remain unresolved" in finding.confidence_reason


def test_malformed_range_candidate_remains_indeterminate_low_confidence() -> None:
    item = candidate(
        affected=Applicability.INDETERMINATE,
        environment=Applicability.INDETERMINATE,
        confidence=Confidence.LOW,
        cvss=CVSSMetric(version="3.1", base_score=9.8),
    )

    finding = generate(port(fp=fingerprint(), candidates=(item,)))[0]

    assert finding.applicability is Applicability.INDETERMINATE
    assert finding.confidence is Confidence.LOW
    assert finding.priority is Priority.MEDIUM
    assert finding.evidence[-1].summary == item.match_reason


@pytest.mark.parametrize(
    ("affected", "environment"),
    [
        (Applicability.NO_MATCH, Applicability.MATCH),
        (Applicability.MATCH, Applicability.NO_MATCH),
    ],
)
def test_no_match_candidate_creates_no_finding(
    affected: Applicability, environment: Applicability
) -> None:
    item = candidate(affected=affected, environment=environment)

    assert generate(port(fp=fingerprint(), candidates=(item,))) == ()


def test_malformed_model_construct_candidate_is_isolated() -> None:
    malformed = VulnerabilityCandidate.model_construct(
        cve_id=None,
        source="nvd",
        description="malformed",
        cvss=None,
        references=(),
        affected_match=Applicability.MATCH,
        environment_applicability=Applicability.MATCH,
        match_confidence=Confidence.HIGH,
        match_reason="malformed",
        fingerprint_evidence_reference="malformed",
        lookup_at=NOW,
        provenance=LookupProvenance.SYNTHETIC,
        metadata={},
    )
    valid = candidate("CVE-2026-1001")

    findings = generate(port(fp=fingerprint(), candidates=(malformed, valid)))

    assert [finding.cve_id for finding in findings] == ["CVE-2026-1001"]


def test_duplicate_candidates_are_deduplicated_with_stable_identity() -> None:
    duplicate = candidate()
    input_port = port(fp=fingerprint(), candidates=(duplicate, duplicate))

    first = generate(input_port)
    second = generate(input_port)

    assert len(first) == 1
    assert first[0].finding_id == second[0].finding_id
    assert first[0].finding_id.startswith("AF-")
    assert len(first[0].finding_id) == 27


def test_generic_remediation_is_explicitly_labeled() -> None:
    finding = generate(port(fp=fingerprint(), candidates=(candidate(),)))[0]

    assert finding.remediation.provenance is RemediationProvenance.GENERIC
    assert finding.remediation.source == "RCScan generic guidance"
    assert "vendor security update" in finding.remediation.text


def test_explicit_provider_remediation_preserves_provenance_and_metadata() -> None:
    item = candidate(
        metadata={
            "remediation": "  Upgrade   to 1.11.  ",
            "remediation_source": "  Vendor advisory  ",
            "advisory_id": "ADV-1",
        }
    )

    finding = generate(port(fp=fingerprint(), candidates=(item,)))[0]

    assert finding.remediation.text == "Upgrade to 1.11."
    assert finding.remediation.source == "Vendor advisory"
    assert finding.remediation.provenance is RemediationProvenance.PROVIDER
    assert finding.provider_provenance is LookupProvenance.SYNTHETIC
    assert finding.metadata["advisory_id"] == "ADV-1"


@pytest.mark.parametrize(
    "metadata",
    [
        {"remediation": "Upgrade now"},
        {"remediation_source": "Vendor advisory"},
        {"remediation": " ", "remediation_source": "Vendor advisory"},
    ],
)
def test_missing_or_partial_remediation_falls_back_to_generic(
    metadata: dict[str, str],
) -> None:
    finding = generate(
        port(fp=fingerprint(), candidates=(candidate(metadata=metadata),))
    )[0]

    assert finding.remediation.provenance is RemediationProvenance.GENERIC


def test_references_are_validated_deduplicated_and_bounded() -> None:
    references = (
        " https://example.test/one ",
        "ftp://example.test/rejected",
        "not a url",
        "https://example.test/one",
        "http://example.test/two",
        "https://example.test/three",
    )

    assert bounded_references(references, limit=2) == (
        "https://example.test/one",
        "http://example.test/two",
    )


def test_finding_reference_limit_is_ten() -> None:
    references = tuple(f"https://example.test/{index}" for index in range(12))

    finding = generate(
        port(fp=fingerprint(), candidates=(candidate(references=references),))
    )[0]

    assert finding.references == references[:10]


@pytest.mark.parametrize(
    "input_port",
    [
        port(fp=fingerprint(service=Service.UNKNOWN), candidates=(candidate(),)),
        port(fp=fingerprint(product=None), candidates=(candidate(),)),
        port(fp=fingerprint(version=None), candidates=(candidate(),)),
        port(fp=None, candidates=(candidate(),)),
        port(
            fp=fingerprint(),
            candidates=(candidate(),),
            state=PortState.CLOSED,
        ),
    ],
)
def test_unknown_or_missing_identity_creates_no_finding(
    input_port: PortResult,
) -> None:
    assert generate(input_port) == ()


def test_empty_candidates_create_no_findings() -> None:
    assert generate(port(fp=fingerprint())) == ()


def test_multiple_ports_and_cves_create_distinct_ordered_findings() -> None:
    findings = generate(
        port(
            80,
            fp=fingerprint(),
            candidates=(candidate("CVE-2026-1000"), candidate("CVE-2026-1001")),
        ),
        port(
            443,
            fp=fingerprint(service=Service.HTTPS),
            candidates=(candidate("CVE-2026-1000"),),
        ),
    )

    assert [(item.port, item.cve_id) for item in findings] == [
        (80, "CVE-2026-1000"),
        (80, "CVE-2026-1001"),
        (443, "CVE-2026-1000"),
    ]
    assert len({item.finding_id for item in findings}) == 3
