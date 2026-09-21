import asyncio
import errno
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from rcscan.network.discovery import TCPDiscovery
from rcscan.network.models import DiscoveryStatus, PortResult, PortState


def port_result(
    state: PortState,
    *,
    port: int = 80,
    latency_ms: float = 3.0,
    error_code: int | None = None,
) -> PortResult:
    return PortResult(
        host="10.0.0.1",
        port=port,
        state=state,
        latency_ms=latency_ms,
        error_code=error_code,
        timestamp=datetime.now(UTC),
    )


@pytest.mark.parametrize("state", [PortState.OPEN, PortState.CLOSED])
def test_open_or_refused_port_proves_host_reachable(state: PortState) -> None:
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (port_result(state, latency_ms=1.25),)
    discovery = TCPDiscovery(scanner, ports=(80,), timeout_seconds=0.5)

    result = asyncio.run(discovery.discover("10.0.0.1"))

    assert result.status is DiscoveryStatus.REACHABLE
    assert result.latency_ms == 1.25
    scanner.scan_ports.assert_awaited_once_with(
        "10.0.0.1", (80,), timeout_seconds=0.5, retries=0
    )


def test_timeout_is_inconclusive() -> None:
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (port_result(PortState.FILTERED),)

    result = asyncio.run(
        TCPDiscovery(scanner, ports=(443,), timeout_seconds=1).discover("10.0.0.1")
    )

    assert result.status is DiscoveryStatus.INCONCLUSIVE


@pytest.mark.parametrize("code", [errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065])
def test_explicit_routing_errors_are_unreachable(code: int) -> None:
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (
        port_result(PortState.ERROR, port=80, error_code=code),
        port_result(PortState.ERROR, port=443, error_code=code),
    )

    result = asyncio.run(
        TCPDiscovery(scanner, ports=(80, 443), timeout_seconds=1).discover("10.0.0.1")
    )

    assert result.status is DiscoveryStatus.UNREACHABLE


def test_mixed_or_unknown_errors_remain_inconclusive() -> None:
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (
        port_result(PortState.ERROR, error_code=errno.EHOSTUNREACH),
        port_result(PortState.ERROR, port=443, error_code=errno.EACCES),
    )

    result = asyncio.run(
        TCPDiscovery(scanner, ports=(80, 443), timeout_seconds=1).discover("10.0.0.1")
    )

    assert result.status is DiscoveryStatus.INCONCLUSIVE
