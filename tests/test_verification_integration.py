import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from rcscan.cli.main import app
from rcscan.core.config import (
    AppConfig,
    FindingsConfig,
    ScopeConfig,
    VerificationConfig,
    VulnerabilityConfig,
)
from rcscan.findings.models import (
    Finding,
    FindingType,
    Priority,
    RemediationGuidance,
    RemediationProvenance,
    Severity,
)
from rcscan.fingerprint.models import Confidence, Service
from rcscan.models.scan import Scan, ScanStatus
from rcscan.network.errors import TargetExpansionError
from rcscan.network.models import (
    DiscoveryMethod,
    DiscoveryStatus,
    HostScanResult,
    PortResult,
    PortState,
    ScanRunResult,
)
from rcscan.scope.parser import parse_target
from rcscan.services.scan_runner import ScanRunner
from rcscan.verification.base import stable_verification_id
from rcscan.verification.models import (
    VerificationEvidence,
    VerificationResult,
    VerificationStatus,
)
from rcscan.vuln.models import Applicability, LookupProvenance

NOW = datetime(2026, 1, 2, tzinfo=UTC)
CLI = CliRunner()


def scan(target: str = "10.0.0.1") -> Scan:
    parsed = parse_target(target)
    return Scan(
        targets=(parsed,),
        authorized_scope=(parsed,),
        profile_name="test",
        ports=(80,),
        authorization_confirmed=True,
    )


def finding(index: int = 0) -> Finding:
    return Finding(
        finding_id=f"AF-{index:024x}",
        title="Synthetic demo finding",
        type=FindingType.KNOWN_VULNERABILITY,
        host="10.0.0.1",
        port=80,
        service=Service.HTTP,
        product="RCScanDemo",
        version="1.0.0",
        cve_id="CVE-DEMO-M6-0001",
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


def verification(
    item: Finding,
    summary: str = "Exact bounded marker observed.",
) -> VerificationResult:
    return VerificationResult(
        finding_id=item.finding_id,
        verification_id=stable_verification_id(
            item.finding_id, "synthetic-http-marker", "rcscan-m6-demo-marker"
        ),
        verifier_name="synthetic-http-marker",
        rule_id="rcscan-m6-demo-marker",
        status=VerificationStatus.VERIFIED,
        confidence=Confidence.HIGH,
        evidence=(VerificationEvidence(summary=summary),),
        reason="Expected synthetic marker observed.",
        requests_attempted=1,
        duration_ms=1,
        generated_at=NOW,
    )


def port() -> PortResult:
    return PortResult(
        host="10.0.0.1",
        port=80,
        state=PortState.OPEN,
        latency_ms=1,
        timestamp=NOW,
    )


def host() -> HostScanResult:
    return HostScanResult(
        target="10.0.0.1",
        resolved_address="10.0.0.1",
        discovery_status=DiscoveryStatus.SKIPPED,
        discovery_method=DiscoveryMethod.SKIPPED,
        discovery_latency_ms=None,
        ports=(port(),),
        started_at=NOW,
        completed_at=NOW,
    )


def completed(
    *,
    findings: tuple[Finding, ...] = (),
    verification_results: tuple[VerificationResult, ...] = (),
) -> ScanRunResult:
    return ScanRunResult(
        scan_id=scan().scan_id,
        status=ScanStatus.COMPLETED,
        targets_requested=1,
        hosts_expanded=1,
        hosts=(host(),),
        started_at=NOW,
        completed_at=NOW,
        findings=findings,
        verification_results=verification_results,
    )


def config(*, verification_enabled: bool = False, findings_displayed: int = 20) -> AppConfig:
    return AppConfig(
        vulnerability=VulnerabilityConfig(cache_enabled=False),
        verification=VerificationConfig(enabled=verification_enabled),
        findings=FindingsConfig(max_displayed=findings_displayed),
    )


def dependencies() -> tuple[AsyncMock, MagicMock, AsyncMock]:
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (port(),)
    findings = MagicMock()
    findings.generate.return_value = (finding(),)
    verifier = AsyncMock()
    verifier.verify.return_value = (verification(finding()),)
    return scanner, findings, verifier


@pytest.mark.parametrize(
    ("configured_enabled", "flag_enabled", "expected"),
    [(False, False, 0), (False, True, 1), (True, False, 1)],
)
def test_runner_verification_default_and_explicit_enablement(
    configured_enabled: bool, flag_enabled: bool, expected: int
) -> None:
    scanner, findings, verifier = dependencies()
    result = asyncio.run(
        ScanRunner(
            config(verification_enabled=configured_enabled),
            scanner=scanner,
            finding_engine=findings,
            verification_engine=verifier,
        ).run(
            scan(),
            skip_discovery=True,
            no_fingerprint=True,
            active_verification=flag_enabled,
        )
    )
    assert result.status is ScanStatus.COMPLETED
    assert verifier.verify.await_count == expected
    assert len(result.verification_results) == expected


def test_zero_findings_make_zero_verification_calls() -> None:
    scanner, findings, verifier = dependencies()
    findings.generate.return_value = ()
    result = asyncio.run(
        ScanRunner(
            config(verification_enabled=True),
            scanner=scanner,
            finding_engine=findings,
            verification_engine=verifier,
        ).run(scan(), skip_discovery=True, no_fingerprint=True)
    )
    assert result.findings == ()
    assert result.verification_results == ()
    verifier.verify.assert_not_awaited()


@pytest.mark.parametrize(
    "options",
    [
        {"vulnerability_lookup": False},
        {"no_fingerprint": True},
    ],
)
def test_disabled_lookup_or_fingerprinting_naturally_yields_zero_verification(
    options: dict[str, bool],
) -> None:
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (port(),)
    fingerprinter = AsyncMock()
    vulnerability = AsyncMock()
    verifier = AsyncMock()

    result = asyncio.run(
        ScanRunner(
            AppConfig(
                vulnerability=VulnerabilityConfig(enabled=True, cache_enabled=False),
                verification=VerificationConfig(enabled=True),
            ),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            vulnerability_engine=vulnerability,
            verification_engine=verifier,
        ).run(scan(), skip_discovery=True, **options)
    )
    assert result.findings == ()
    assert result.verification_results == ()
    verifier.verify.assert_not_awaited()
    if options.get("no_fingerprint"):
        fingerprinter.fingerprint_ports.assert_not_awaited()
        vulnerability.enrich_hosts.assert_not_awaited()
    else:
        vulnerability.enrich_hosts.assert_not_awaited()


def test_verification_stage_exception_preserves_findings_and_completed_status() -> None:
    scanner, findings, verifier = dependencies()
    verifier.verify.side_effect = RuntimeError("whole stage failed")
    result = asyncio.run(
        ScanRunner(
            config(verification_enabled=True),
            scanner=scanner,
            finding_engine=findings,
            verification_engine=verifier,
        ).run(scan(), skip_discovery=True, no_fingerprint=True)
    )
    assert result.status is ScanStatus.COMPLETED
    assert result.findings == (finding(),)
    assert result.verification_results == ()


def test_verification_cancellation_propagates_and_marks_scan_cancelled() -> None:
    scanner, findings, verifier = dependencies()
    verifier.verify.side_effect = asyncio.CancelledError
    runner = ScanRunner(
        config(verification_enabled=True),
        scanner=scanner,
        finding_engine=findings,
        verification_engine=verifier,
    )
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(runner.run(scan(), skip_discovery=True, no_fingerprint=True))
    assert runner.current_scan is not None
    assert runner.current_scan.status is ScanStatus.CANCELLED


def invoke(run: ScanRunResult, *extra: str, settings: AppConfig | None = None):
    with (
        patch("rcscan.cli.main.load_config", return_value=settings or config()),
        patch("rcscan.cli.main._run_with_progress", return_value=run) as execute,
    ):
        result = CLI.invoke(
            app,
            [
                "scan",
                "--target",
                "10.0.0.1",
                "--scope",
                "10.0.0.0/8",
                "--confirm-authorized",
                *extra,
            ],
        )
    return result, execute


@pytest.mark.parametrize(
    ("flag", "keyword", "expected"),
    [
        ("--active-verification", "active_verification", True),
        ("--web-discovery", "web_discovery", True),
        ("--web-checks", "web_checks", True),
        ("--active-web-checks", "active_web_checks", True),
        ("--no-vuln-lookup", "vulnerability_lookup", False),
        ("--no-fingerprint", "no_fingerprint", True),
    ],
)
def test_cli_forwards_verification_related_flags(
    flag: str, keyword: str, expected: bool
) -> None:
    result, execute = invoke(completed(), flag)
    assert result.exit_code == 0
    assert execute.call_args.kwargs[keyword] is expected


@pytest.mark.parametrize(
    ("settings", "extra"),
    [
        (config(verification_enabled=True), ()),
        (config(), ("--active-verification",)),
    ],
)
def test_cli_announces_enabled_verification(
    settings: AppConfig, extra: tuple[str, ...]
) -> None:
    result, _ = invoke(completed(), *extra, settings=settings)
    assert result.exit_code == 0
    assert "Active verification: ENABLED" in result.output


def test_cli_renders_nested_verification_evidence_with_finding_bound() -> None:
    first, second = finding(), finding(1)
    run = completed(
        findings=(first, second),
        verification_results=(
            verification(first, "FIRST_BOUNDED_EVIDENCE"),
            verification(second, "SECOND_HIDDEN_EVIDENCE"),
        ),
    )
    result, _ = invoke(run, settings=config(findings_displayed=1))
    assert result.exit_code == 0
    assert "Verification:" in result.output
    assert "Status: VERIFIED" in result.output
    assert "FIRST_BOUNDED_EVIDENCE" in result.output
    assert "SECOND_HIDDEN_EVIDENCE" not in result.output
    assert "1 additional findings not displayed" in result.output


@pytest.mark.parametrize(
    "arguments",
    [
        ("--target", "10.0.0.1", "--scope", "10.0.0.0/8"),
        (
            "--target",
            "10.0.0.1",
            "--scope",
            "192.168.0.0/16",
            "--confirm-authorized",
        ),
        (
            "--target",
            "127.0.0.1",
            "--scope",
            "127.0.0.0/8",
            "--confirm-authorized",
        ),
        (
            "--target",
            "203.0.113.9",
            "--scope",
            "203.0.113.0/24",
            "--confirm-authorized",
        ),
        (
            "--target",
            "authorized-public.example",
            "--scope",
            "authorized-public.example",
            "--confirm-authorized",
        ),
        (
            "--target",
            "public-a.example",
            "--scope",
            "public-b.example",
            "--allow-public-targets",
            "--confirm-authorized",
        ),
        (
            "--target",
            "authorized-public.example",
            "--scope",
            "authorized-public.example",
            "--allow-public-targets",
        ),
    ],
)
def test_rejected_scope_makes_zero_calls_at_every_active_stage(
    arguments: tuple[str, ...],
) -> None:
    with (
        patch("asyncio.open_connection", new=AsyncMock()) as connect,
        patch(
            "rcscan.fingerprint.engine.FingerprintEngine.fingerprint_ports",
            new=AsyncMock(),
        ) as fingerprints,
        patch(
            "rcscan.vuln.providers.nvd.NVDProvider.search_product",
            new=AsyncMock(),
        ) as provider,
        patch("rcscan.findings.engine.FindingEngine.generate") as findings,
        patch(
            "rcscan.verification.engine.VerificationEngine.verify",
            new=AsyncMock(),
        ) as verification_stage,
        patch(
            "rcscan.verification.http.VerificationHttpClient.request",
            new=AsyncMock(),
        ) as verification_probe,
        patch(
            "rcscan.web.crawler.WebCrawler.discover",
            new=AsyncMock(),
        ) as web_stage,
        patch(
            "rcscan.web.http.WebHttpClient.get",
            new=AsyncMock(),
        ) as web_request,
        patch(
            "rcscan.web_security.engine.WebSecurityEngine.analyze",
        ) as web_checks,
        patch(
            "rcscan.active_web.engine.ActiveWebSecurityEngine.analyze",
            new=AsyncMock(),
        ) as active_web_checks,
    ):
        result = CLI.invoke(
            app,
            [
                "scan",
                *arguments,
                "--vuln-lookup",
                "--active-verification",
                "--web-discovery",
                "--web-checks",
                "--active-web-checks",
            ],
        )
    assert result.exit_code == 2
    connect.assert_not_awaited()
    fingerprints.assert_not_awaited()
    provider.assert_not_awaited()
    findings.assert_not_called()
    verification_stage.assert_not_awaited()
    verification_probe.assert_not_awaited()
    web_stage.assert_not_awaited()
    web_request.assert_not_awaited()
    web_checks.assert_not_called()
    active_web_checks.assert_not_awaited()


def test_oversized_expansion_makes_zero_calls_at_every_active_stage() -> None:
    target = parse_target("10.0.0.0/30")
    oversized = Scan(
        targets=(target,),
        authorized_scope=(target,),
        profile_name="test",
        ports=(80,),
        authorization_confirmed=True,
    )
    scanner = AsyncMock()
    fingerprinter = AsyncMock()
    vulnerability = AsyncMock()
    findings = MagicMock()
    verifier = AsyncMock()
    with pytest.raises(TargetExpansionError):
        asyncio.run(
            ScanRunner(
                AppConfig(scope=ScopeConfig(max_targets=1)),
                scanner=scanner,
                fingerprint_engine=fingerprinter,
                vulnerability_engine=vulnerability,
                finding_engine=findings,
                verification_engine=verifier,
            ).run(
                oversized,
                vulnerability_lookup=True,
                active_verification=True,
            )
        )
    scanner.scan_ports.assert_not_awaited()
    fingerprinter.fingerprint_ports.assert_not_awaited()
    vulnerability.enrich_hosts.assert_not_awaited()
    findings.generate.assert_not_called()
    verifier.verify.assert_not_awaited()
