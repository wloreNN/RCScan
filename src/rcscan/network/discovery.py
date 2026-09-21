"""TCP-based host discovery with conservative reachability semantics."""

from __future__ import annotations

import logging

from rcscan.network.errors import is_explicitly_unreachable
from rcscan.network.models import (
    DiscoveryMethod,
    DiscoveryResult,
    DiscoveryStatus,
    PortState,
)
from rcscan.network.tcp_scanner import TCPScanner


class TCPDiscovery:
    """Infer limited host reachability evidence from safe TCP connects."""

    def __init__(
        self,
        scanner: TCPScanner,
        *,
        ports: tuple[int, ...],
        timeout_seconds: float,
    ) -> None:
        self._scanner = scanner
        self._ports = tuple(dict.fromkeys(ports))
        self._timeout_seconds = timeout_seconds
        self._logger = logging.getLogger(__name__)

    async def discover(self, host: str) -> DiscoveryResult:
        results = await self._scanner.scan_ports(
            host,
            self._ports,
            timeout_seconds=self._timeout_seconds,
            retries=0,
        )
        responsive = tuple(
            result
            for result in results
            if result.state in {PortState.OPEN, PortState.CLOSED}
        )
        if responsive:
            result = DiscoveryResult(
                status=DiscoveryStatus.REACHABLE,
                method=DiscoveryMethod.TCP_CONNECT,
                latency_ms=min(item.latency_ms for item in responsive),
            )
        elif results and all(
            item.state is PortState.ERROR and is_explicitly_unreachable(item.error_code)
            for item in results
        ):
            result = DiscoveryResult(
                status=DiscoveryStatus.UNREACHABLE,
                method=DiscoveryMethod.TCP_CONNECT,
                latency_ms=min(item.latency_ms for item in results),
                error="The operating system reported the host or network unreachable.",
            )
        else:
            result = DiscoveryResult(
                status=DiscoveryStatus.INCONCLUSIVE,
                method=DiscoveryMethod.TCP_CONNECT,
                latency_ms=min((item.latency_ms for item in results), default=None),
                error="No conclusive response was received from discovery probes.",
            )
        self._logger.debug(
            "Host discovery target=%s status=%s",
            host,
            result.status.value,
        )
        return result


def skipped_discovery() -> DiscoveryResult:
    return DiscoveryResult(
        status=DiscoveryStatus.SKIPPED,
        method=DiscoveryMethod.SKIPPED,
    )
