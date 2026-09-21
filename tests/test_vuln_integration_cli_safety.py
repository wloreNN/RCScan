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
    VulnerabilityConfig,
)
from rcscan.findings.engine import FindingEngine
from rcscan.fingerprint.models import Confidence, Service, ServiceFingerprint
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
from rcscan.vuln.models import (
    Applicability,
    CandidateStatus,
    CVSSMetric,
    LookupProvenance,
    VulnerabilityCandidate,
)

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
    *,
    state: PortState = PortState.OPEN,
    fp: ServiceFingerprint | None = None,
) -> PortResult:
    return PortResult(
        host="10.0.0.1",
        port=80,
        state=state,
        latency_ms=1,
        timestamp=NOW,
        fingerprint=fp,
    )


def host(*ports: PortResult) -> HostScanResult:
    return HostScanResult(
        target="10.0.0.1",
        resolved_address="10.0.0.1",
        discovery_status=DiscoveryStatus.SKIPPED,
        discovery_method=DiscoveryMethod.SKIPPED,
        discovery_latency_ms=None,
        ports=ports,
        started_at=NOW,
        completed_at=NOW,
    )


def configured(
    enabled: bool = False,
    *,
    displayed: int = 10,
    findings_enabled: bool = True,
    findings_displayed: int = 20,
) -> AppConfig:
    return AppConfig(
        vulnerability=VulnerabilityConfig(
            enabled=enabled,
            cache_enabled=False,
            max_displayed_candidates=displayed,
        ),
        findings=FindingsConfig(
            enabled=findings_enabled,
            max_displayed=findings_displayed,
        ),
    )


def runner_dependencies() -> tuple[AsyncMock, AsyncMock, AsyncMock]:
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (port(),)
    fingerprinter = AsyncMock()
    fingerprinter.fingerprint_ports.return_value = (port(fp=fingerprint()),)
    vulnerability = AsyncMock()
    vulnerability.enrich_hosts.side_effect = lambda hosts: hosts
    return scanner, fingerprinter, vulnerability


@pytest.mark.parametrize(
    ("config_enabled", "override", "expected"),
    [(False, None, 0), (False, False, 0), (False, True, 1), (True, None, 1), (True, False, 0)],
)
def test_runner_lookup_default_and_explicit_override(
    config_enabled: bool, override: bool | None, expected: int
) -> None:
    scanner, fingerprinter, vulnerability = runner_dependencies()
    result = asyncio.run(
        ScanRunner(
            configured(config_enabled),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            vulnerability_engine=vulnerability,
        ).run(scan(), skip_discovery=True, vulnerability_lookup=override)
    )
    assert result.status is ScanStatus.COMPLETED
    assert vulnerability.enrich_hosts.await_count == expected


def test_lookup_runs_after_fingerprint_stage() -> None:
    events: list[str] = []
    scanner, fingerprinter, vulnerability = runner_dependencies()

    async def fingerprint_stage(**_kwargs):
        events.append("fingerprint")
        return (port(fp=fingerprint()),)

    async def lookup_stage(hosts):
        assert hosts[0].ports[0].fingerprint is not None
        events.append("lookup")
        return hosts

    fingerprinter.fingerprint_ports.side_effect = fingerprint_stage
    vulnerability.enrich_hosts.side_effect = lookup_stage
    asyncio.run(
        ScanRunner(
            configured(True),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            vulnerability_engine=vulnerability,
        ).run(scan(), skip_discovery=True)
    )
    assert events == ["fingerprint", "lookup"]


def test_runner_orders_scan_fingerprint_lookup_and_findings_stages() -> None:
    events: list[str] = []
    scanner, fingerprinter, vulnerability = runner_dependencies()
    findings = MagicMock()

    async def scan_stage(*_args, **_kwargs):
        events.append("scan")
        return (port(),)

    async def fingerprint_stage(**_kwargs):
        events.append("fingerprint")
        return (port(fp=fingerprint()),)

    async def lookup_stage(hosts):
        events.append("lookup")
        return hosts

    def finding_stage(hosts):
        assert hosts[0].ports[0].fingerprint is not None
        events.append("findings")
        return ()

    scanner.scan_ports.side_effect = scan_stage
    fingerprinter.fingerprint_ports.side_effect = fingerprint_stage
    vulnerability.enrich_hosts.side_effect = lookup_stage
    findings.generate.side_effect = finding_stage

    result = asyncio.run(
        ScanRunner(
            configured(True),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            vulnerability_engine=vulnerability,
            finding_engine=findings,
        ).run(scan(), skip_discovery=True)
    )

    assert result.status is ScanStatus.COMPLETED
    assert events == ["scan", "fingerprint", "lookup", "findings"]


def test_disabled_vulnerability_lookup_yields_no_findings() -> None:
    scanner, fingerprinter, vulnerability = runner_dependencies()

    result = asyncio.run(
        ScanRunner(
            configured(False),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            vulnerability_engine=vulnerability,
            finding_engine=FindingEngine(),
        ).run(scan(), skip_discovery=True)
    )

    vulnerability.enrich_hosts.assert_not_awaited()
    assert result.findings == ()


def test_findings_disabled_skips_engine() -> None:
    scanner, fingerprinter, vulnerability = runner_dependencies()
    findings = MagicMock()

    result = asyncio.run(
        ScanRunner(
            configured(findings_enabled=False),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            vulnerability_engine=vulnerability,
            finding_engine=findings,
        ).run(scan(), skip_discovery=True)
    )

    assert result.status is ScanStatus.COMPLETED
    findings.generate.assert_not_called()
    assert result.findings == ()


def test_finding_stage_failure_preserves_completed_scan_and_evidence() -> None:
    scanner, fingerprinter, vulnerability = runner_dependencies()
    findings = MagicMock()
    enriched_port = port(fp=fingerprint()).model_copy(
        update={"vulnerability_candidates": (candidate("CVE-2026-1000"),)}
    )

    async def enrich(_hosts):
        return (host(enriched_port),)

    vulnerability.enrich_hosts.side_effect = enrich
    findings.generate.side_effect = RuntimeError("finding stage failed")

    result = asyncio.run(
        ScanRunner(
            configured(True),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            vulnerability_engine=vulnerability,
            finding_engine=findings,
        ).run(scan(), skip_discovery=True)
    )

    assert result.status is ScanStatus.COMPLETED
    assert result.hosts[0].ports[0].fingerprint == fingerprint()
    assert result.hosts[0].ports[0].vulnerability_candidates == (
        candidate("CVE-2026-1000"),
    )
    assert result.findings == ()


def test_provider_failure_data_still_completes_scan() -> None:
    scanner, fingerprinter, vulnerability = runner_dependencies()

    async def unavailable(hosts):
        failed = hosts[0].ports[0].model_copy(
            update={"vulnerability_lookup_error": "NVD temporarily unavailable"}
        )
        return (hosts[0].model_copy(update={"ports": (failed,)}),)

    vulnerability.enrich_hosts.side_effect = unavailable
    result = asyncio.run(
        ScanRunner(
            configured(True),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            vulnerability_engine=vulnerability,
        ).run(scan(), skip_discovery=True)
    )
    assert result.status is ScanStatus.COMPLETED
    assert result.hosts[0].ports[0].vulnerability_lookup_error


def test_no_fingerprint_flag_makes_zero_lookup_requests() -> None:
    scanner, fingerprinter, vulnerability = runner_dependencies()
    asyncio.run(
        ScanRunner(
            configured(True),
            scanner=scanner,
            fingerprint_engine=fingerprinter,
            vulnerability_engine=vulnerability,
        ).run(scan(), skip_discovery=True, no_fingerprint=True)
    )
    fingerprinter.fingerprint_ports.assert_not_awaited()
    vulnerability.enrich_hosts.assert_not_awaited()


def cli_result(*ports: PortResult) -> ScanRunResult:
    return ScanRunResult(
        scan_id=scan().scan_id,
        status=ScanStatus.COMPLETED,
        targets_requested=1,
        hosts_expanded=1,
        hosts=(host(*ports),),
        started_at=NOW,
        completed_at=NOW,
    )


def invoke(run: ScanRunResult, *extra: str, config: AppConfig | None = None):
    with (
        patch("rcscan.cli.main.load_config", return_value=config or configured()),
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
    ("flag", "expected"),
    [("--vuln-lookup", True), ("--no-vuln-lookup", False)],
)
def test_cli_forwards_vulnerability_lookup_override(flag: str, expected: bool) -> None:
    result, execute = invoke(cli_result(), flag)
    assert result.exit_code == 0
    assert execute.call_args.kwargs["vulnerability_lookup"] is expected


def test_cli_rejects_mutually_exclusive_lookup_flags_without_execution() -> None:
    result, execute = invoke(cli_result(), "--vuln-lookup", "--no-vuln-lookup")
    assert result.exit_code == 2
    assert "cannot be combined" in result.output
    execute.assert_not_called()


def candidate(cve_id: str) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        cve_id=cve_id,
        source="nvd",
        status=CandidateStatus.POTENTIAL_MATCH,
        description="description",
        cvss=CVSSMetric(version="3.1", base_score=9.8, base_severity="CRITICAL"),
        affected_match=Applicability.MATCH,
        environment_applicability=Applicability.MATCH,
        match_confidence=Confidence.HIGH,
        match_reason="Observed version matches a published affected version range.",
        fingerprint_evidence_reference="nginx 1.10",
        lookup_at=NOW,
        provenance=LookupProvenance.SYNTHETIC,
    )


def test_cli_candidate_wording_is_non_assertive_and_output_is_bounded() -> None:
    candidates = tuple(candidate(f"CVE-2026-{1000 + index}") for index in range(4))
    enriched = port(fp=fingerprint()).model_copy(
        update={"vulnerability_candidates": candidates}
    )
    result, _ = invoke(cli_result(enriched), config=configured(displayed=2))
    assert result.exit_code == 0
    assert "Potential vulnerability matches" in result.output
    assert "POTENTIAL_MATCH" in result.output
    assert "CVE-2026-1000" in result.output
    assert "CVE-2026-1001" in result.output
    assert "CVE-2026-1002" not in result.output
    assert "2 additional candidates not displayed" in result.output
    assert "Published CVSS 3.1: 9.8 CRITICAL" in result.output
    assert "Match confidence: HIGH" in result.output


def test_cli_findings_are_non_assertive_and_globally_bounded() -> None:
    candidates = tuple(candidate(f"CVE-2026-{1000 + index}") for index in range(3))
    enriched = port(fp=fingerprint()).model_copy(
        update={"vulnerability_candidates": candidates}
    )
    findings = FindingEngine().generate((host(enriched),))
    run = cli_result().model_copy(update={"findings": findings})

    result, _ = invoke(
        run,
        config=configured(findings_displayed=2),
    )

    assert result.exit_code == 0
    assert "Findings" in result.output
    assert "Potential known vulnerability" in result.output
    assert "Applicability: MATCH" in result.output
    assert "CVE-2026-1000" in result.output
    assert "CVE-2026-1001" in result.output
    assert "CVE-2026-1002" not in result.output
    assert "1 additional findings not displayed" in result.output
    assert "is vulnerable" not in result.output


def test_cli_renders_provider_unavailable_without_failing() -> None:
    failed = port(fp=fingerprint()).model_copy(
        update={"vulnerability_lookup_error": "NVD temporarily unavailable"}
    )
    result, _ = invoke(cli_result(failed))
    assert result.exit_code == 0
    assert "Vulnerability intelligence unavailable" in result.output
    assert "NVD temporarily unavailable" in result.output
    assert "COMPLETED" in result.output


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
    ],
)
def test_rejected_cli_scope_makes_zero_connections_fingerprints_and_provider_requests(
    arguments: tuple[str, ...],
) -> None:
    with (
        patch("asyncio.open_connection", new=AsyncMock()) as connect,
        patch(
            "rcscan.fingerprint.engine.FingerprintEngine.fingerprint_ports",
            new=AsyncMock(),
        ) as fingerprint_ports,
        patch(
            "rcscan.vuln.providers.nvd.NVDProvider.search_product",
            new=AsyncMock(),
        ) as lookup,
        patch(
            "rcscan.findings.engine.FindingEngine.generate",
        ) as generate_findings,
    ):
        result = CLI.invoke(app, ["scan", *arguments, "--vuln-lookup"])
    assert result.exit_code == 2
    connect.assert_not_awaited()
    fingerprint_ports.assert_not_awaited()
    lookup.assert_not_awaited()
    generate_findings.assert_not_called()


def test_oversized_expansion_makes_zero_scan_fingerprint_and_lookup_calls() -> None:
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
    with pytest.raises(TargetExpansionError):
        asyncio.run(
            ScanRunner(
                AppConfig(scope=ScopeConfig(max_targets=1)),
                scanner=scanner,
                fingerprint_engine=fingerprinter,
                vulnerability_engine=vulnerability,
                finding_engine=findings,
            ).run(oversized, vulnerability_lookup=True)
        )
    scanner.scan_ports.assert_not_awaited()
    fingerprinter.fingerprint_ports.assert_not_awaited()
    vulnerability.enrich_hosts.assert_not_awaited()
    findings.generate.assert_not_called()
