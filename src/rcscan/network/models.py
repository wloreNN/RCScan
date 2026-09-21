"""Structured network execution models for Milestone 2."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from rcscan.findings.models import Finding
from rcscan.fingerprint.models import ServiceFingerprint
from rcscan.models.scan import ScanStatus
from rcscan.verification.models import VerificationResult
from rcscan.vuln.models import VulnerabilityCandidate
from rcscan.web.models import WebDiscoveryResult


class Protocol(StrEnum):
    TCP = "TCP"


class PortState(StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    ERROR = "ERROR"


class DiscoveryStatus(StrEnum):
    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    SKIPPED = "SKIPPED"


class DiscoveryMethod(StrEnum):
    TCP_CONNECT = "TCP_CONNECT"
    SKIPPED = "SKIPPED"
    DNS_FAILURE = "DNS_FAILURE"
    POLICY_BLOCKED = "POLICY_BLOCKED"


class ExpandedHost(BaseModel):
    """One concrete host derived from an already-authorized target."""

    model_config = ConfigDict(frozen=True)

    target: str
    address: str | None
    hostname: str | None = None


class PortResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    host: str
    port: int
    protocol: Protocol = Protocol.TCP
    state: PortState
    latency_ms: float
    error_code: int | None = None
    error_message: str | None = None
    timestamp: datetime
    fingerprint: ServiceFingerprint | None = None
    vulnerability_candidates: tuple[VulnerabilityCandidate, ...] = ()
    vulnerability_lookup_error: str | None = None


class DiscoveryResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: DiscoveryStatus
    method: DiscoveryMethod
    latency_ms: float | None = None
    error: str | None = None


class HostScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    resolved_address: str | None
    discovery_status: DiscoveryStatus
    discovery_method: DiscoveryMethod
    discovery_latency_ms: float | None
    ports: tuple[PortResult, ...]
    started_at: datetime
    completed_at: datetime
    error: str | None = None
    scan_skipped_reason: str | None = None
    discovery_error: str | None = None

    @property
    def open_ports(self) -> tuple[PortResult, ...]:
        return tuple(result for result in self.ports if result.state is PortState.OPEN)

    @property
    def closed_ports(self) -> tuple[PortResult, ...]:
        return tuple(result for result in self.ports if result.state is PortState.CLOSED)

    @property
    def filtered_ports(self) -> tuple[PortResult, ...]:
        return tuple(result for result in self.ports if result.state is PortState.FILTERED)

    @property
    def error_ports(self) -> tuple[PortResult, ...]:
        return tuple(result for result in self.ports if result.state is PortState.ERROR)


class ScanRunResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    scan_id: UUID
    status: ScanStatus
    targets_requested: int
    hosts_expanded: int
    hosts: tuple[HostScanResult, ...]
    started_at: datetime
    completed_at: datetime
    findings: tuple[Finding, ...] = ()
    verification_results: tuple[VerificationResult, ...] = ()
    web_discovery_results: tuple[WebDiscoveryResult, ...] = ()
    web_findings: tuple[Finding, ...] = ()
    active_web_findings: tuple[Finding, ...] = ()

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.completed_at - self.started_at).total_seconds())

    @property
    def hosts_reachable(self) -> int:
        return sum(host.discovery_status is DiscoveryStatus.REACHABLE for host in self.hosts)

    @property
    def hosts_inconclusive(self) -> int:
        return sum(host.discovery_status is DiscoveryStatus.INCONCLUSIVE for host in self.hosts)

    @property
    def hosts_scanned(self) -> int:
        return sum(bool(host.ports) for host in self.hosts)

    @property
    def ports_attempted(self) -> int:
        return sum(len(host.ports) for host in self.hosts)

    @property
    def open_ports(self) -> int:
        return sum(len(host.open_ports) for host in self.hosts)

    @property
    def closed_ports(self) -> int:
        return sum(len(host.closed_ports) for host in self.hosts)

    @property
    def filtered_ports(self) -> int:
        return sum(len(host.filtered_ports) for host in self.hosts)

    @property
    def errors(self) -> int:
        host_errors = sum(host.error is not None for host in self.hosts)
        discovery_errors = sum(
            host.discovery_status is DiscoveryStatus.UNREACHABLE for host in self.hosts
        )
        return (
            host_errors
            + discovery_errors
            + sum(len(host.error_ports) for host in self.hosts)
        )
