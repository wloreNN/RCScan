import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from rcscan.cli.main import app
from rcscan.core.config import AppConfig, ScopeConfig
from rcscan.models.scan import Scan
from rcscan.network.errors import TargetExpansionError
from rcscan.scope.parser import parse_target
from rcscan.services.scan_runner import ScanRunner
from rcscan.services.scan_service import ScanService

runner = CliRunner()


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (
            ("--target", "10.0.0.1", "--scope", "10.0.0.0/8"),
            "Authorization confirmation is required",
        ),
        (
            (
                "--target",
                "10.0.0.1",
                "--scope",
                "192.168.0.0/16",
                "--confirm-authorized",
            ),
            "outside the explicitly authorized scope",
        ),
        (
            (
                "--target",
                "127.0.0.1",
                "--scope",
                "127.0.0.0/8",
                "--confirm-authorized",
            ),
            "Loopback target",
        ),
        (
            (
                "--target",
                "203.0.113.9",
                "--scope",
                "203.0.113.0/24",
                "--confirm-authorized",
            ),
            "Public target",
        ),
    ],
)
def test_rejected_cli_inputs_make_zero_network_calls(
    arguments: tuple[str, ...], message: str
) -> None:
    with (
        patch(
            "asyncio.open_connection",
            new=AsyncMock(side_effect=AssertionError("network call")),
        ) as connect,
        patch(
            "socket.getaddrinfo",
            side_effect=AssertionError("DNS call"),
        ) as resolve,
        patch("rcscan.cli.main._run_with_progress") as execute,
    ):
        result = runner.invoke(app, ["scan", *arguments])

    assert result.exit_code == 2
    assert message in result.output
    connect.assert_not_awaited()
    resolve.assert_not_called()
    execute.assert_not_called()


def test_oversized_expansion_makes_zero_connector_calls() -> None:
    target = parse_target("10.0.0.0/30")
    scan = Scan(
        targets=(target,),
        authorized_scope=(target,),
        profile_name="test",
        ports=(80,),
        authorization_confirmed=True,
    )
    connector = AsyncMock(side_effect=AssertionError("network call"))
    config = AppConfig(scope=ScopeConfig(max_targets=1))
    runner_under_test = ScanRunner(config)
    runner_under_test._scanner._connector = connector

    with pytest.raises(TargetExpansionError, match="no network activity"):
        asyncio.run(runner_under_test.run(scan))

    connector.assert_not_awaited()


def test_hostname_resolving_to_blocked_loopback_makes_zero_network_calls() -> None:
    config = AppConfig(
        scope=ScopeConfig(allow_public_targets=True, allow_loopback=False)
    )
    scan = ScanService(config).create_scan(
        target_value="host.example",
        targets_file=None,
        scope_value="host.example",
        ports_value="80",
        authorization_confirmed=True,
        allow_loopback=False,
    )
    scanner = AsyncMock()
    scanner.scan_ports.return_value = ()
    resolver = AsyncMock(return_value="127.0.0.1")

    asyncio.run(
        ScanRunner(config, scanner=scanner, resolver=resolver).run(
            scan, skip_discovery=True
        )
    )

    scanner.scan_ports.assert_not_awaited()
