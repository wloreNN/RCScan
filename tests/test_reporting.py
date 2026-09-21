import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from rcscan.findings.models import (
    EvidenceType,
    Finding,
    FindingEvidence,
    FindingType,
    Priority,
    RemediationGuidance,
    RemediationProvenance,
    Severity,
)
from rcscan.fingerprint.models import (
    Confidence,
    EvidenceSource,
    FingerprintEvidence,
    Service,
    ServiceFingerprint,
)
from rcscan.models.scan import Scan, ScanStatus
from rcscan.network.models import (
    DiscoveryMethod,
    DiscoveryStatus,
    HostScanResult,
    PortResult,
    PortState,
    ScanRunResult,
)
from rcscan.reporting import (
    ReportFeatures,
    build_report,
    write_html_report,
    write_json_report,
    write_sarif_report,
)
from rcscan.scope.parser import parse_target
from rcscan.vuln.models import (
    Applicability,
    LookupProvenance,
    VulnerabilityCandidate,
)

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
SECRETS = (
    "secret-token",
    "supersecret",
    "TOPSECRET",
    "hunter2",
    "api-key-value",
)


def features() -> ReportFeatures:
    return ReportFeatures(
        fingerprinting=True,
        vulnerability_lookup=False,
        active_verification=False,
        web_discovery=True,
        web_checks=True,
        active_web_checks=True,
    )


def scan() -> Scan:
    target = parse_target("site.example")
    return Scan(
        scan_id=UUID(int=7),
        targets=(target,),
        authorized_scope=(target,),
        profile_name="safe-default",
        ports=(443,),
        status=ScanStatus.COMPLETED,
        created_at=NOW,
        authorization_confirmed=True,
    )


def finding(*, suffix: str = "1") -> Finding:
    return Finding(
        finding_id=f"AF-{'0' * 23}{suffix}",
        title="Potential issue <script>alert(1)</script>",
        type=FindingType.INFORMATION_DISCLOSURE,
        host="site.example",
        port=443,
        service=Service.HTTPS,
        description="Potential synthetic issue",
        evidence=(
            FindingEvidence(
                type=EvidenceType.OBSERVED,
                summary=(
                    "Authorization: Bearer secret-token "
                    "Cookie=session=supersecret "
                    "<script>alert(1)</script>"
                ),
            ),
        ),
        applicability=Applicability.MATCH,
        confidence=Confidence.HIGH,
        confidence_reason="Repeated bounded observation",
        severity=Severity.MEDIUM,
        priority=Priority.MEDIUM,
        remediation=RemediationGuidance(
            text="Use contextual encoding and strict input validation.",
            provenance=RemediationProvenance.GENERIC,
            source="RCScan guidance",
        ),
        references=("https://example.test/advisory",),
        source="active-web-test-rule",
        provider_provenance=LookupProvenance.LOCAL_ANALYSIS,
        first_observed=NOW,
        metadata={
            "category": "POTENTIAL_TEST_WITH_A_VERY_LONG_CATEGORY_IDENTIFIER",
            "affected_url": (
                "https://site.example/asset/a-very-long-resource-path-that-must-wrap"
                "?q=visible-value-that-remains-useful-in-the-report"
                "&token=TOPSECRET&password=hunter2"
            ),
            "parameter": "q",
            "rule_id": "active-web-test-rule",
            "rule_family": "synthetic-family",
            "platform": "UNIX",
            "confirmation_status": "CONFIRMED_BY_REPEAT",
            "Authorization": "Bearer secret-token",
            "Cookie": "session=supersecret",
            "Set-Cookie": "session=supersecret",
            "x-api-key": "api-key-value",
            "ordinary": "visible",
        },
    )


def result(*findings: Finding) -> ScanRunResult:
    fingerprint = ServiceFingerprint(
        service=Service.HTTPS,
        product="Synthetic",
        version="1.0",
        confidence=Confidence.HIGH,
        evidence=(
            FingerprintEvidence(
                source=EvidenceSource.HTTP_RESPONSE,
                summary="Observed bounded HTTPS response",
                timestamp=NOW,
            ),
        ),
        probe_used="HEAD",
        encrypted=True,
        metadata={"tls_version": "TLSv1.3"},
    )
    port = PortResult(
        host="203.0.113.10",
        port=443,
        state=PortState.OPEN,
        latency_ms=2,
        timestamp=NOW,
        fingerprint=fingerprint,
        vulnerability_candidates=(
            VulnerabilityCandidate(
                cve_id="CVE-2026-1234",
                source="synthetic-provider",
                description="Potential correlated advisory",
                affected_match=Applicability.MATCH,
                environment_applicability=Applicability.INDETERMINATE,
                match_confidence=Confidence.MEDIUM,
                match_reason="Product and version correlation only",
                fingerprint_evidence_reference="bounded HTTPS response",
                lookup_at=NOW,
                provenance=LookupProvenance.SYNTHETIC,
            ),
        ),
    )
    host = HostScanResult(
        target="site.example",
        resolved_address="203.0.113.10",
        discovery_status=DiscoveryStatus.REACHABLE,
        discovery_method=DiscoveryMethod.TCP_CONNECT,
        discovery_latency_ms=1,
        ports=(port,),
        started_at=NOW,
        completed_at=NOW,
    )
    return ScanRunResult(
        scan_id=UUID(int=7),
        status=ScanStatus.COMPLETED,
        targets_requested=1,
        hosts_expanded=1,
        hosts=(host,),
        started_at=NOW,
        completed_at=NOW,
        active_web_findings=findings,
    )


def assert_no_secrets(payload: str) -> None:
    assert all(secret not in payload for secret in SECRETS)
    assert "[REDACTED]" in payload


def test_canonical_report_contains_network_and_structured_finding_data() -> None:
    report = build_report(scan(), result(finding()), features=features())
    assert report.schema_version == "1.0"
    assert report.scan.targets == ("site.example",)
    assert report.hosts[0].ports[0].service == "HTTPS"
    assert report.hosts[0].ports[0].tls_metadata["tls_version"] == "TLSv1.3"
    candidate = report.hosts[0].ports[0].vulnerability_candidates[0]
    assert candidate.advisory_id == "CVE-2026-1234"
    assert candidate.environment_applicability == "INDETERMINATE"
    item = report.findings[0]
    assert item.parameter == "q"
    assert item.rule_family == "synthetic-family"
    assert item.platform == "UNIX"
    assert item.confirmation == "CONFIRMED_BY_REPEAT"
    assert item.reproduction.method == "GET"
    assert item.metadata["ordinary"] == "visible"


def test_json_is_valid_stable_and_redacted(tmp_path: Path) -> None:
    report = build_report(scan(), result(finding()), features=features())
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    write_json_report(report, first)
    write_json_report(report, second)
    payload = first.read_text(encoding="utf-8")
    document = json.loads(payload)
    assert payload == second.read_text(encoding="utf-8")
    assert document["schema_version"] == "1.0"
    assert document["schema"].endswith("/report/v1")
    assert document["findings"][0]["severity"] == "MEDIUM"
    assert_no_secrets(payload)


def test_html_is_self_contained_escaped_and_redacted(tmp_path: Path) -> None:
    report = build_report(scan(), result(finding()), features=features())
    path = tmp_path / "report.html"
    write_html_report(report, path)
    payload = path.read_text(encoding="utf-8")
    assert "<!doctype html>" in payload
    assert "RCScan Security Assessment" in payload
    assert "Findings Overview" in payload
    assert "Priority: MEDIUM" in payload
    assert '<span class="fact-label">Platform</span>UNIX' in payload
    assert "visible-value-that-remains-useful-in-the-report" in payload
    assert "POTENTIAL_TEST_WITH_A_VERY_LONG_CATEGORY_IDENTIFIER" in payload
    assert "overflow-wrap:anywhere" in payload
    assert "@media print" in payload
    assert "Reproduction Evidence" in payload
    assert "Use contextual encoding" in payload
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in payload
    assert "<script>alert(1)</script>" not in payload
    assert "cdn." not in payload.casefold()
    assert_no_secrets(payload)


def test_sarif_uses_remote_uri_without_fake_line_numbers(tmp_path: Path) -> None:
    report = build_report(
        scan(),
        result(finding(suffix="1"), finding(suffix="2")),
        features=features(),
    )
    path = tmp_path / "report.sarif"
    write_sarif_report(report, path)
    payload = path.read_text(encoding="utf-8")
    document = json.loads(payload)
    run = document["runs"][0]
    assert document["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "RCScan"
    assert len(run["results"]) == 2
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"].startswith("https://site.example/")
    assert "region" not in location
    assert run["results"][0]["properties"]["confidence"] == "HIGH"
    assert_no_secrets(payload)


def test_empty_report_renders_in_all_formats(tmp_path: Path) -> None:
    report = build_report(scan(), result(), features=features())
    write_json_report(report, tmp_path / "empty.json")
    write_html_report(report, tmp_path / "empty.html")
    write_sarif_report(report, tmp_path / "empty.sarif")
    assert report.findings == ()
    assert "No findings were generated" in (
        tmp_path / "empty.html"
    ).read_text(encoding="utf-8")
    assert json.loads((tmp_path / "empty.sarif").read_text())["runs"][0][
        "results"
    ] == []
