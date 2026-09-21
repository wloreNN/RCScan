import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from rcscan.cli.main import app
from rcscan.core.config import AppConfig
from rcscan.fingerprint.engine import FingerprintEngine
from rcscan.fingerprint.evidence import make_evidence
from rcscan.fingerprint.models import (
    Confidence,
    EvidenceSource,
    Service,
    ServiceFingerprint,
)
from rcscan.fingerprint.probes import ReadProbeResult
from rcscan.models.scan import Scan, ScanStatus
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

cli = CliRunner()


def scan() -> Scan:
    target = parse_target("10.0.0.1")
    return Scan(
        targets=(target,),
        authorized_scope=(target,),
        profile_name="test",
        ports=(22, 23),
        authorization_confirmed=True,
    )


def port(number: int, state: PortState) -> PortResult:
    return PortResult(
        host="10.0.0.1",
        port=number,
        state=state,
        latency_ms=1,
        timestamp=datetime.now(UTC),
    )


def test_scan_runner_attaches_fingerprint_only_to_open_ports() -> None:
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (
        port(22, PortState.OPEN),
        port(23, PortState.CLOSED),
    )
    probe = AsyncMock()
    probe.passive_banner.return_value = ReadProbeResult(
        data=b"SSH-2.0-OpenSSH_9.8\r\n", latency_ms=1
    )
    fingerprint_engine = FingerprintEngine(
        probe_client=probe,
        concurrency=2,
        max_probes_per_port=3,
    )

    result = asyncio.run(
        ScanRunner(
            AppConfig(),
            scanner=scanner,
            fingerprint_engine=fingerprint_engine,
        ).run(scan(), skip_discovery=True)
    )

    assert result.hosts[0].ports[0].fingerprint is not None
    assert result.hosts[0].ports[0].fingerprint.service is Service.SSH
    assert result.hosts[0].ports[1].fingerprint is None
    probe.passive_banner.assert_awaited_once_with("10.0.0.1", 22)


def test_scan_runner_no_fingerprint_makes_zero_fingerprint_calls() -> None:
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (port(22, PortState.OPEN),)
    fingerprint_engine = AsyncMock()

    result = asyncio.run(
        ScanRunner(
            AppConfig(),
            scanner=scanner,
            fingerprint_engine=fingerprint_engine,
        ).run(scan(), skip_discovery=True, no_fingerprint=True)
    )

    assert result.hosts[0].ports[0].fingerprint is None
    fingerprint_engine.fingerprint_ports.assert_not_awaited()


def fingerprint(
    service: Service,
    *,
    product: str | None = None,
    version: str | None = None,
) -> ServiceFingerprint:
    return ServiceFingerprint(
        service=service,
        product=product,
        version=version,
        confidence=Confidence.HIGH if service is not Service.UNKNOWN else Confidence.LOW,
        evidence=(
            make_evidence(
                EvidenceSource.SERVER_BANNER,
                "Valid bounded evidence.",
                b"banner\x1b[31m\r\n",
            ),
        ),
        probe_used="Passive banner",
        encrypted=False,
        metadata={"protocol_version": "2.0"},
    )


def cli_result(*ports: PortResult) -> ScanRunResult:
    now = datetime.now(UTC)
    host = HostScanResult(
        target="10.0.0.1",
        resolved_address="10.0.0.1",
        discovery_status=DiscoveryStatus.REACHABLE,
        discovery_method=DiscoveryMethod.TCP_CONNECT,
        discovery_latency_ms=1,
        ports=ports,
        started_at=now,
        completed_at=now,
    )
    return ScanRunResult(
        scan_id=scan().scan_id,
        status=ScanStatus.COMPLETED,
        targets_requested=1,
        hosts_expanded=1,
        hosts=(host,),
        started_at=now,
        completed_at=now,
    )


def invoke_with(run: ScanRunResult, *extra: str):
    with patch("rcscan.cli.main._run_with_progress", return_value=run) as execute:
        result = cli.invoke(
            app,
            [
                "scan",
                "--target",
                "10.0.0.1",
                "--scope",
                "10.0.0.0/8",
                "--ports",
                "22",
                "--confirm-authorized",
                *extra,
            ],
        )
    return result, execute


def test_cli_renders_known_and_unknown_fingerprints_conservatively() -> None:
    known = port(22, PortState.OPEN).model_copy(
        update={"fingerprint": fingerprint(Service.SSH, product="OpenSSH", version="9.8")}
    )
    unknown = port(23, PortState.OPEN).model_copy(
        update={"fingerprint": fingerprint(Service.UNKNOWN)}
    )

    result, _ = invoke_with(cli_result(known, unknown))

    assert result.exit_code == 0
    assert "Service     SSH" in result.output
    assert "Product     OpenSSH" in result.output
    assert "Version     9.8" in result.output
    assert "Service     UNKNOWN" in result.output
    assert result.output.count("Confidence  HIGH") == 1
    assert "Valid bounded evidence" not in result.output


def test_cli_verbose_renders_safe_evidence_probe_and_metadata() -> None:
    known = port(22, PortState.OPEN).model_copy(
        update={"fingerprint": fingerprint(Service.SSH, product="OpenSSH")}
    )

    result, _ = invoke_with(cli_result(known), "--verbose")

    assert result.exit_code == 0
    assert "Probe        Passive banner" in result.output
    assert "Evidence     Valid bounded evidence." in result.output
    assert r"banner\x1b[31m\r\n" in result.output
    assert "\x1b[31m" not in result.output
    assert "protocol_version 2.0" in result.output


def test_cli_forwards_no_fingerprint_flag() -> None:
    result, execute = invoke_with(cli_result(), "--no-fingerprint")

    assert result.exit_code == 0
    assert execute.call_args.kwargs["no_fingerprint"] is True
