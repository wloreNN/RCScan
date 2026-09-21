import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from rcscan.core.config import AppConfig
from rcscan.models.scan import Scan, ScanStatus
from rcscan.network.models import (
    DiscoveryMethod,
    DiscoveryResult,
    DiscoveryStatus,
    PortResult,
    PortState,
)
from rcscan.scope.parser import parse_target
from rcscan.services.scan_runner import ScanRunner


def make_scan(target: str = "10.0.0.1") -> Scan:
    parsed = parse_target(target)
    return Scan(
        targets=(parsed,),
        authorized_scope=(parsed,),
        profile_name="test",
        ports=(80,),
        authorization_confirmed=True,
    )


def discovery(status: DiscoveryStatus) -> DiscoveryResult:
    return DiscoveryResult(
        status=status,
        method=DiscoveryMethod.TCP_CONNECT,
        latency_ms=1,
    )


def open_port(host: str = "10.0.0.1") -> PortResult:
    return PortResult(
        host=host,
        port=80,
        state=PortState.OPEN,
        latency_ms=2,
        timestamp=datetime.now(UTC),
    )


def dependencies(status: DiscoveryStatus = DiscoveryStatus.REACHABLE):
    scanner = AsyncMock()
    scanner.scan_ports.return_value = (open_port(),)
    detector = AsyncMock()
    detector.discover.return_value = discovery(status)
    return scanner, detector


def test_status_transitions_to_completed_and_updates_current_scan() -> None:
    scanner, detector = dependencies()
    statuses: list[ScanStatus] = []
    runner = ScanRunner(
        AppConfig(),
        scanner=scanner,
        discovery=detector,
        on_status=lambda scan: statuses.append(scan.status),
    )

    result = asyncio.run(runner.run(make_scan(), no_fingerprint=True))

    assert result.status is ScanStatus.COMPLETED
    assert statuses == [ScanStatus.RUNNING, ScanStatus.COMPLETED]
    assert runner.current_scan is not None
    assert runner.current_scan.status is ScanStatus.COMPLETED


def test_failure_transitions_to_failed_and_updates_current_scan() -> None:
    scanner, detector = dependencies()
    detector.discover.side_effect = RuntimeError("boom")
    runner = ScanRunner(AppConfig(), scanner=scanner, discovery=detector)

    with pytest.raises(RuntimeError, match="boom"):
        asyncio.run(runner.run(make_scan(), no_fingerprint=True))

    assert runner.current_scan is not None
    assert runner.current_scan.status is ScanStatus.FAILED


def test_cancellation_transitions_to_cancelled_and_updates_current_scan() -> None:
    scanner, detector = dependencies()
    detector.discover.side_effect = asyncio.CancelledError
    runner = ScanRunner(AppConfig(), scanner=scanner, discovery=detector)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(runner.run(make_scan(), no_fingerprint=True))

    assert runner.current_scan is not None
    assert runner.current_scan.status is ScanStatus.CANCELLED


def test_hostname_resolution_preserves_target_and_uses_resolved_address() -> None:
    scanner, detector = dependencies()
    scanner.scan_ports.return_value = (open_port("10.0.0.9"),)
    resolver = AsyncMock(return_value="10.0.0.9")
    runner = ScanRunner(
        AppConfig(),
        scanner=scanner,
        discovery=detector,
        resolver=resolver,
    )

    result = asyncio.run(runner.run(make_scan("host.internal"), no_fingerprint=True))

    host = result.hosts[0]
    assert host.target == "host.internal"
    assert host.resolved_address == "10.0.0.9"
    resolver.assert_awaited_once_with("host.internal")
    detector.discover.assert_awaited_once_with("10.0.0.9")
    scanner.scan_ports.assert_awaited_once_with(
        "10.0.0.9", (80,), on_result=None
    )


def test_hostname_resolution_failure_is_reported_without_probes() -> None:
    scanner, detector = dependencies()
    resolver = AsyncMock(side_effect=OSError("not found"))
    runner = ScanRunner(
        AppConfig(),
        scanner=scanner,
        discovery=detector,
        resolver=resolver,
    )

    result = asyncio.run(runner.run(make_scan("host.internal"), no_fingerprint=True))

    host = result.hosts[0]
    assert host.resolved_address is None
    assert host.discovery_method is DiscoveryMethod.DNS_FAILURE
    assert "not found" in (host.error or "")
    detector.discover.assert_not_awaited()
    scanner.scan_ports.assert_not_awaited()


def test_inconclusive_discovery_skips_port_scan_by_default() -> None:
    scanner, detector = dependencies(DiscoveryStatus.INCONCLUSIVE)

    result = asyncio.run(
        ScanRunner(AppConfig(), scanner=scanner, discovery=detector).run(
            make_scan(), no_fingerprint=True
        )
    )

    assert result.hosts[0].ports == ()
    assert "inconclusive" in (result.hosts[0].scan_skipped_reason or "")
    scanner.scan_ports.assert_not_awaited()


def test_assume_up_scans_after_inconclusive_discovery() -> None:
    scanner, detector = dependencies(DiscoveryStatus.INCONCLUSIVE)

    result = asyncio.run(
        ScanRunner(AppConfig(), scanner=scanner, discovery=detector).run(
            make_scan(), assume_up=True, no_fingerprint=True
        )
    )

    assert result.hosts[0].ports
    scanner.scan_ports.assert_awaited_once()


def test_skip_discovery_scans_directly() -> None:
    scanner, detector = dependencies()

    result = asyncio.run(
        ScanRunner(AppConfig(), scanner=scanner, discovery=detector).run(
            make_scan(), skip_discovery=True, no_fingerprint=True
        )
    )

    assert result.hosts[0].discovery_status is DiscoveryStatus.SKIPPED
    detector.discover.assert_not_awaited()
    scanner.scan_ports.assert_awaited_once()
