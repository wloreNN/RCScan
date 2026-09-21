import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from rcscan.cli.main import app
from rcscan.core.config import AppConfig, FingerprintingConfig, ScopeConfig
from rcscan.fingerprint.engine import FingerprintEngine
from rcscan.models.scan import Scan
from rcscan.network.errors import TargetExpansionError
from rcscan.network.models import PortResult, PortState
from rcscan.scope.parser import parse_target
from rcscan.services.scan_runner import ScanRunner
from rcscan.services.scan_service import ScanService

cli = CliRunner()


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
    ids=["unauthorized", "out-of-scope", "blocked-loopback", "blocked-public"],
)
def test_rejected_targets_make_zero_fingerprint_calls(arguments: tuple[str, ...]) -> None:
    with patch(
        "rcscan.fingerprint.engine.FingerprintEngine.fingerprint_ports",
        new=AsyncMock(side_effect=AssertionError("fingerprint call")),
    ) as fingerprint_ports:
        result = cli.invoke(app, ["scan", *arguments])

    assert result.exit_code == 2
    fingerprint_ports.assert_not_awaited()


def make_scan(target_value: str, *, ports: tuple[int, ...] = (80,)) -> Scan:
    target = parse_target(target_value)
    return Scan(
        targets=(target,),
        authorized_scope=(target,),
        profile_name="test",
        ports=ports,
        authorization_confirmed=True,
    )


def test_oversized_expansion_makes_zero_fingerprint_calls() -> None:
    scanner = AsyncMock()
    fingerprint_engine = AsyncMock()
    runner = ScanRunner(
        AppConfig(scope=ScopeConfig(max_targets=1)),
        scanner=scanner,
        fingerprint_engine=fingerprint_engine,
    )

    with pytest.raises(TargetExpansionError):
        asyncio.run(runner.run(make_scan("10.0.0.0/30")))

    scanner.scan_ports.assert_not_awaited()
    fingerprint_engine.fingerprint_ports.assert_not_awaited()


@pytest.mark.parametrize(
    "state",
    [PortState.CLOSED, PortState.FILTERED, PortState.ERROR],
)
def test_non_open_ports_make_zero_application_probe_calls(state: PortState) -> None:
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (
        PortResult(
            host="10.0.0.1",
            port=80,
            state=state,
            latency_ms=1,
            timestamp=datetime.now(UTC),
        ),
    )
    probe = AsyncMock()
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
        ).run(make_scan("10.0.0.1"), skip_discovery=True)
    )

    assert result.hosts[0].ports[0].fingerprint is None
    probe.passive_banner.assert_not_awaited()
    probe.tls.assert_not_awaited()
    probe.http.assert_not_awaited()


def test_disabled_fingerprinting_config_makes_zero_fingerprint_calls() -> None:
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (
        PortResult(
            host="10.0.0.1",
            port=80,
            state=PortState.OPEN,
            latency_ms=1,
            timestamp=datetime.now(UTC),
        ),
    )
    fingerprint_engine = AsyncMock()
    config = AppConfig(fingerprinting=FingerprintingConfig(enabled=False))

    asyncio.run(
        ScanRunner(
            config,
            scanner=scanner,
            fingerprint_engine=fingerprint_engine,
        ).run(make_scan("10.0.0.1"), skip_discovery=True)
    )

    fingerprint_engine.fingerprint_ports.assert_not_awaited()


def test_no_fingerprint_flag_makes_zero_calls_even_for_open_port() -> None:
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (
        PortResult(
            host="10.0.0.1",
            port=80,
            state=PortState.OPEN,
            latency_ms=1,
            timestamp=datetime.now(UTC),
        ),
    )
    fingerprint_engine = AsyncMock()

    asyncio.run(
        ScanRunner(
            AppConfig(),
            scanner=scanner,
            fingerprint_engine=fingerprint_engine,
        ).run(
            make_scan("10.0.0.1"),
            skip_discovery=True,
            no_fingerprint=True,
        )
    )

    fingerprint_engine.fingerprint_ports.assert_not_awaited()


def test_hostname_resolving_to_blocked_loopback_makes_zero_fingerprint_calls() -> None:
    config = AppConfig(scope=ScopeConfig(allow_public_targets=True))
    scan = ScanService(config).create_scan(
        target_value="unit.example",
        targets_file=None,
        scope_value="unit.example",
        ports_value="80",
        authorization_confirmed=True,
        allow_loopback=False,
    )
    scanner = AsyncMock()
    fingerprint_engine = AsyncMock()

    result = asyncio.run(
        ScanRunner(
            config,
            scanner=scanner,
            resolver=AsyncMock(return_value="127.0.0.1"),
            fingerprint_engine=fingerprint_engine,
        ).run(scan, skip_discovery=True)
    )

    assert result.hosts[0].ports == ()
    scanner.scan_ports.assert_not_awaited()
    fingerprint_engine.fingerprint_ports.assert_not_awaited()
