"""Execute validated scans through discovery and bounded TCP connects."""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from ipaddress import IPv4Address

from rcscan.active_web.engine import ActiveWebSecurityEngine
from rcscan.core.config import AppConfig
from rcscan.findings.engine import FindingEngine
from rcscan.findings.models import Finding
from rcscan.fingerprint.engine import FingerprintEngine
from rcscan.fingerprint.probes import ProbeClient
from rcscan.models.scan import Scan, ScanStatus
from rcscan.network.discovery import TCPDiscovery, skipped_discovery
from rcscan.network.errors import ScanExecutionError
from rcscan.network.expansion import expand_targets
from rcscan.network.models import (
    DiscoveryMethod,
    DiscoveryStatus,
    HostScanResult,
    PortResult,
    ScanRunResult,
)
from rcscan.network.tcp_scanner import TCPScanner
from rcscan.verification.engine import VerificationEngine
from rcscan.verification.http import VerificationHttpClient
from rcscan.verification.models import VerificationResult
from rcscan.vuln.cache import VulnerabilityCache, default_cache_path
from rcscan.vuln.engine import VulnerabilityEngine
from rcscan.vuln.providers.nvd import NVDProvider
from rcscan.web.crawler import WebCrawler
from rcscan.web.models import WebDiscoveryResult
from rcscan.web.request_context import WebRequestContext
from rcscan.web.throttle import OriginThrottleCoordinator
from rcscan.web_security.engine import WebSecurityEngine

Resolver = Callable[[str], Awaitable[str]]
PlanCallback = Callable[[int, int], None]
PortCallback = Callable[[PortResult], None]
HostCallback = Callable[[HostScanResult], None]
StatusCallback = Callable[[Scan], None]


class ScanRunner:
    """Own scan lifecycle transitions and all post-validation network activity."""

    def __init__(
        self,
        config: AppConfig,
        *,
        scanner: TCPScanner | None = None,
        discovery: TCPDiscovery | None = None,
        fingerprint_engine: FingerprintEngine | None = None,
        vulnerability_engine: VulnerabilityEngine | None = None,
        finding_engine: FindingEngine | None = None,
        verification_engine: VerificationEngine | None = None,
        web_crawler: WebCrawler | None = None,
        web_security_engine: WebSecurityEngine | None = None,
        active_web_security_engine: ActiveWebSecurityEngine | None = None,
        request_context: WebRequestContext | None = None,
        resolver: Resolver | None = None,
        on_status: StatusCallback | None = None,
    ) -> None:
        self._config = config
        self._request_context = request_context or WebRequestContext()
        throttle_settings = config.web_throttling
        self._throttle = OriginThrottleCoordinator(
            min_request_interval_seconds=(
                throttle_settings.min_request_interval_seconds
            ),
            max_retry_after_seconds=throttle_settings.max_retry_after_seconds,
            max_transient_retries=throttle_settings.max_transient_retries,
        )
        self._scanner = scanner or TCPScanner(
            timeout_seconds=config.scanner.timeout_seconds,
            concurrency=config.scanner.concurrency,
            retries=config.scanner.retries,
        )
        self._discovery = discovery or TCPDiscovery(
            self._scanner,
            ports=config.discovery.ports,
            timeout_seconds=config.discovery.timeout_seconds,
        )
        self._fingerprint_engine = fingerprint_engine or FingerprintEngine(
            probe_client=ProbeClient(
                timeout_seconds=config.fingerprinting.timeout_seconds,
                max_banner_bytes=config.fingerprinting.max_banner_bytes,
                max_header_bytes=config.fingerprinting.max_header_bytes,
                request_context=self._request_context,
                throttle=self._throttle,
            ),
            concurrency=config.fingerprinting.concurrency,
            max_probes_per_port=config.fingerprinting.max_probes_per_port,
        )
        self._vulnerability_engine = vulnerability_engine or _vulnerability_engine(config)
        self._finding_engine = finding_engine or FindingEngine()
        self._verification_engine = verification_engine or _verification_engine(
            config,
            self._request_context,
            self._throttle,
        )
        self._web_crawler = web_crawler or _web_crawler(
            config,
            self._request_context,
            self._throttle,
        )
        self._web_security_engine = web_security_engine or WebSecurityEngine()
        self._active_web_security_engine = (
            active_web_security_engine
            or _active_web_security_engine(
                config,
                self._request_context,
                self._throttle,
            )
        )
        self._resolver = resolver or resolve_hostname_ipv4
        self._on_status = on_status
        self._logger = logging.getLogger(__name__)
        self.current_scan: Scan | None = None

    async def run(
        self,
        scan: Scan,
        *,
        skip_discovery: bool = False,
        assume_up: bool = False,
        no_fingerprint: bool = False,
        vulnerability_lookup: bool | None = None,
        active_verification: bool = False,
        web_discovery: bool = False,
        web_checks: bool = False,
        active_web_checks: bool = False,
        on_plan: PlanCallback | None = None,
        on_port: PortCallback | None = None,
        on_host: HostCallback | None = None,
    ) -> ScanRunResult:
        if skip_discovery and assume_up:
            raise ScanExecutionError("--skip-discovery and --assume-up cannot be used together.")
        if not scan.authorization_confirmed:
            raise ScanExecutionError("Cannot execute a scan without authorization confirmation.")
        if scan.status is not ScanStatus.PENDING:
            raise ScanExecutionError("Only a PENDING scan can be executed.")

        self._set_status(scan, ScanStatus.RUNNING)
        started_at = datetime.now(UTC)
        self._logger.info("Scan started id=%s", scan.scan_id)
        try:
            expanded = expand_targets(scan.targets, self._config.scope.max_targets)
            if on_plan is not None:
                on_plan(len(expanded), len(expanded) * len(scan.ports))

            host_results: list[HostScanResult] = []
            for host in expanded:
                host_result = await self._scan_host(
                    host.target,
                    host.address,
                    host.hostname,
                    scan.ports,
                    skip_discovery=skip_discovery,
                    assume_up=assume_up,
                    no_fingerprint=no_fingerprint,
                    loopback_allowed=scan.loopback_allowed,
                    on_port=on_port,
                )
                host_results.append(host_result)
                if on_host is not None:
                    on_host(host_result)

            web_discovery_results: tuple[WebDiscoveryResult, ...] = ()
            web_checks_enabled = self._config.web_checks.enabled or web_checks
            active_web_checks_enabled = (
                self._config.active_web_checks.enabled or active_web_checks
            )
            web_discovery_enabled = (
                self._config.web_discovery.enabled
                or web_discovery
                or web_checks_enabled
                or active_web_checks_enabled
            )
            if web_discovery_enabled:
                try:
                    web_discovery_results = await self._web_crawler.discover(
                        tuple(host_results)
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self._logger.debug(
                        "Web discovery failed; preserving existing scan evidence",
                        exc_info=True,
                    )

            web_findings: tuple[Finding, ...] = ()
            if web_checks_enabled and web_discovery_results:
                try:
                    web_findings = self._web_security_engine.analyze(
                        web_discovery_results
                    )
                except Exception:
                    self._logger.debug(
                        "Web security checks failed; preserving discovery evidence",
                        exc_info=True,
                    )

            active_web_findings: tuple[Finding, ...] = ()
            if active_web_checks_enabled and web_discovery_results:
                try:
                    active_web_findings = (
                        await self._active_web_security_engine.analyze(
                            web_discovery_results
                        )
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self._logger.debug(
                        "Active web checks failed; preserving prior evidence",
                        exc_info=True,
                    )

            lookup_enabled = (
                self._config.vulnerability.enabled
                if vulnerability_lookup is None
                else vulnerability_lookup
            )
            if lookup_enabled and not no_fingerprint:
                host_results = list(
                    await self._vulnerability_engine.enrich_hosts(tuple(host_results))
                )

            findings: tuple[Finding, ...] = ()
            if self._config.findings.enabled:
                try:
                    findings = self._finding_engine.generate(tuple(host_results))
                except Exception:
                    self._logger.debug(
                        "Finding generation failed; preserving scan evidence",
                        exc_info=True,
                    )

            verification_results: tuple[VerificationResult, ...] = ()
            verification_enabled = self._config.verification.enabled or active_verification
            if verification_enabled and findings:
                try:
                    verification_results = await self._verification_engine.verify(findings)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self._logger.debug(
                        "Verification stage failed; preserving M2-M5 evidence",
                        exc_info=True,
                    )

            completed_at = datetime.now(UTC)
            self._set_status(scan, ScanStatus.COMPLETED)
            run_result = ScanRunResult(
                scan_id=scan.scan_id,
                status=ScanStatus.COMPLETED,
                targets_requested=len(scan.targets),
                hosts_expanded=len(expanded),
                hosts=tuple(host_results),
                started_at=started_at,
                completed_at=completed_at,
                findings=findings,
                verification_results=verification_results,
                web_discovery_results=web_discovery_results,
                web_findings=web_findings,
                active_web_findings=active_web_findings,
            )
            self._logger.info(
                "Scan completed id=%s hosts=%d ports=%d duration_seconds=%.3f",
                scan.scan_id,
                run_result.hosts_scanned,
                run_result.ports_attempted,
                run_result.duration_seconds,
            )
            return run_result
        except asyncio.CancelledError:
            self._set_status(scan, ScanStatus.CANCELLED)
            self._logger.warning("Scan cancelled id=%s", scan.scan_id)
            raise
        except Exception:
            self._set_status(scan, ScanStatus.FAILED)
            self._logger.error("Scan failed id=%s", scan.scan_id)
            raise

    async def _scan_host(
        self,
        target: str,
        address: str | None,
        hostname: str | None,
        ports: tuple[int, ...],
        *,
        skip_discovery: bool,
        assume_up: bool,
        no_fingerprint: bool,
        loopback_allowed: bool,
        on_port: PortCallback | None,
    ) -> HostScanResult:
        started_at = datetime.now(UTC)
        if address is None:
            try:
                resolved = IPv4Address(await self._resolver(target))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                return HostScanResult(
                    target=target,
                    resolved_address=None,
                    discovery_status=DiscoveryStatus.SKIPPED,
                    discovery_method=DiscoveryMethod.DNS_FAILURE,
                    discovery_latency_ms=None,
                    ports=(),
                    started_at=started_at,
                    completed_at=datetime.now(UTC),
                    error=f"IPv4 resolution failed: {exc}",
                    scan_skipped_reason="Port scan skipped because hostname resolution failed.",
                )
            if resolved.is_loopback and not loopback_allowed:
                return HostScanResult(
                    target=target,
                    resolved_address=str(resolved),
                    discovery_status=DiscoveryStatus.SKIPPED,
                    discovery_method=DiscoveryMethod.POLICY_BLOCKED,
                    discovery_latency_ms=None,
                    ports=(),
                    started_at=started_at,
                    completed_at=datetime.now(UTC),
                    error="Resolved loopback address is blocked by policy.",
                    scan_skipped_reason=(
                        "Port scan skipped because the hostname resolved to loopback "
                        "without explicit loopback permission."
                    ),
                )
            address = str(resolved)

        if skip_discovery or not self._config.discovery.enabled:
            discovery_result = skipped_discovery()
            should_scan = True
            skipped_reason = None
        else:
            discovery_result = await self._discovery.discover(address)
            should_scan = discovery_result.status is DiscoveryStatus.REACHABLE or (
                discovery_result.status is DiscoveryStatus.INCONCLUSIVE and assume_up
            )
            skipped_reason = _skip_reason(discovery_result.status) if not should_scan else None

        port_results = (
            await self._scanner.scan_ports(address, ports, on_result=on_port)
            if should_scan
            else ()
        )
        if (
            port_results
            and self._config.fingerprinting.enabled
            and not no_fingerprint
        ):
            port_results = await self._fingerprint_engine.fingerprint_ports(
                address=address,
                hostname=hostname,
                ports=port_results,
            )
        return HostScanResult(
            target=target,
            resolved_address=address,
            discovery_status=discovery_result.status,
            discovery_method=discovery_result.method,
            discovery_latency_ms=discovery_result.latency_ms,
            ports=port_results,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            scan_skipped_reason=skipped_reason,
            discovery_error=discovery_result.error,
        )

    def _set_status(self, original: Scan, status: ScanStatus) -> None:
        self.current_scan = original.model_copy(update={"status": status})
        if self._on_status is not None:
            self._on_status(self.current_scan)


async def resolve_hostname_ipv4(hostname: str) -> str:
    """Resolve one authorized hostname to the first unique IPv4 address."""
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(
        hostname,
        None,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
    )
    for record in records:
        address = record[4][0]
        return str(IPv4Address(address))
    raise OSError("No IPv4 address was returned.")


def _skip_reason(status: DiscoveryStatus) -> str:
    if status is DiscoveryStatus.INCONCLUSIVE:
        return (
            "Port scan skipped because host discovery was inconclusive; "
            "use --assume-up to scan after inconclusive discovery."
        )
    return "Port scan skipped because the operating system reported the host unreachable."


def _vulnerability_engine(config: AppConfig) -> VulnerabilityEngine:
    settings = config.vulnerability
    api_key = (
        settings.nvd_api_key.get_secret_value()
        if settings.nvd_api_key is not None
        else None
    )
    provider = NVDProvider(
        api_key=api_key,
        timeout_seconds=settings.request_timeout_seconds,
        max_response_bytes=settings.max_response_bytes,
        max_references=settings.max_references,
        max_records=settings.max_candidates_per_identity,
    )
    cache = (
        VulnerabilityCache(
            settings.cache_path or default_cache_path(),
            ttl_hours=settings.cache_ttl_hours,
            max_entries=settings.max_cache_entries,
        )
        if settings.cache_enabled
        else None
    )
    return VulnerabilityEngine(
        provider,
        cache=cache,
        max_provider_requests=settings.max_provider_requests_per_scan,
        max_candidates_per_identity=settings.max_candidates_per_identity,
    )


def _verification_engine(
    config: AppConfig,
    request_context: WebRequestContext,
    throttle: OriginThrottleCoordinator,
) -> VerificationEngine:
    settings = config.verification
    return VerificationEngine(
        timeout_seconds=settings.timeout_seconds,
        max_response_bytes=settings.max_response_bytes,
        max_requests_per_finding=settings.max_requests_per_finding,
        max_total_requests=settings.max_total_requests,
        concurrency=settings.concurrency,
        client=VerificationHttpClient(
            timeout_seconds=settings.timeout_seconds,
            max_response_bytes=settings.max_response_bytes,
            request_context=request_context,
            throttle=throttle,
        ),
    )


def _web_crawler(
    config: AppConfig,
    request_context: WebRequestContext,
    throttle: OriginThrottleCoordinator,
) -> WebCrawler:
    settings = config.web_discovery
    return WebCrawler(
        max_pages=settings.max_pages,
        max_depth=settings.max_depth,
        concurrency=settings.concurrency,
        timeout_seconds=settings.timeout_seconds,
        max_response_bytes=settings.max_response_bytes,
        max_links_per_page=settings.max_links_per_page,
        request_context=request_context,
        throttle=throttle,
    )


def _active_web_security_engine(
    config: AppConfig,
    request_context: WebRequestContext,
    throttle: OriginThrottleCoordinator,
) -> ActiveWebSecurityEngine:
    settings = config.active_web_checks
    return ActiveWebSecurityEngine(
        timeout_seconds=settings.timeout_seconds,
        max_response_bytes=settings.max_response_bytes,
        max_requests_per_parameter=settings.max_requests_per_parameter,
        max_total_requests=settings.max_total_requests,
        concurrency=settings.concurrency,
        request_context=request_context,
        throttle=throttle,
    )
