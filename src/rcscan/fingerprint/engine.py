"""Bounded evidence-first service fingerprint orchestration."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable

from rcscan.fingerprint.evidence import make_evidence
from rcscan.fingerprint.models import (
    Confidence,
    EvidenceSource,
    FingerprintEvidence,
    Service,
    ServiceFingerprint,
)
from rcscan.fingerprint.parsers.http import parse_http_response
from rcscan.fingerprint.parsers.ssh import parse_ssh_banner
from rcscan.fingerprint.probes import ProbeClient, TLSProbeResult
from rcscan.network.models import PortResult, PortState

_HTTP_HINTS = {80, 8000, 8080, 8888}
_TLS_HINTS = {443, 8443, 9443}


class FingerprintEngine:
    """Fingerprint only proven-open ports under a separate concurrency bound."""

    def __init__(
        self,
        *,
        probe_client: ProbeClient,
        concurrency: int,
        max_probes_per_port: int,
    ) -> None:
        self._probe_client = probe_client
        self._concurrency = concurrency
        self._max_probes_per_port = max_probes_per_port
        self._semaphore = asyncio.Semaphore(concurrency)
        self._logger = logging.getLogger(__name__)

    async def fingerprint_ports(
        self,
        *,
        address: str,
        hostname: str | None,
        ports: Iterable[PortResult],
    ) -> tuple[PortResult, ...]:
        original = tuple(ports)
        queue: asyncio.Queue[PortResult] = asyncio.Queue()
        for result in original:
            if result.state is PortState.OPEN:
                queue.put_nowait(result)
        if queue.empty():
            return original

        fingerprints: dict[int, ServiceFingerprint] = {}

        async def worker() -> None:
            while True:
                try:
                    port_result = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    fingerprints[port_result.port] = await self.fingerprint_port(
                        address=address,
                        port=port_result.port,
                        hostname=hostname,
                    )
                finally:
                    queue.task_done()

        worker_count = min(self._concurrency, queue.qsize())
        async with asyncio.TaskGroup() as group:
            for _ in range(worker_count):
                group.create_task(worker())

        return tuple(
            result.model_copy(update={"fingerprint": fingerprints[result.port]})
            if result.port in fingerprints
            else result
            for result in original
        )

    async def fingerprint_port(
        self,
        *,
        address: str,
        port: int,
        hostname: str | None,
    ) -> ServiceFingerprint:
        async with self._semaphore:
            try:
                fingerprint = await self._fingerprint_port(
                    address=address,
                    port=port,
                    hostname=hostname,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                fingerprint = _unknown_fingerprint(
                    evidence=(),
                    probes=("internal",),
                    error=_safe_error(exc),
                )
        self._logger.debug(
            "Fingerprint completed host=%s port=%d service=%s confidence=%s",
            address,
            port,
            fingerprint.service.value,
            fingerprint.confidence.value,
        )
        return fingerprint

    async def _fingerprint_port(
        self,
        *,
        address: str,
        port: int,
        hostname: str | None,
    ) -> ServiceFingerprint:
        passive = await self._probe_client.passive_banner(address, port)
        ssh = parse_ssh_banner(passive.data)
        if ssh is not None:
            return ssh

        evidence: list[FingerprintEvidence] = []
        errors: list[str] = []
        probes: list[str] = ["Passive banner"]
        if passive.data:
            evidence.append(
                make_evidence(
                    EvidenceSource.SERVER_BANNER,
                    (
                        "Unrecognized bounded passive banner received"
                        + ("; input exceeded the byte limit." if passive.truncated else ".")
                    ),
                    passive.data,
                )
            )
        if passive.error:
            errors.append(passive.error)

        remaining = self._max_probes_per_port
        if port in _HTTP_HINTS:
            http, used = await self._try_http(
                address=address,
                port=port,
                hostname=hostname,
                use_tls=False,
                remaining=remaining,
                prior_evidence=tuple(evidence),
                prior_metadata=None,
                probes=probes,
                errors=errors,
            )
            remaining -= used
            if http is not None:
                return http
            tls, used = await self._try_tls(
                address,
                port,
                hostname,
                remaining,
                evidence,
                probes,
                errors,
            )
            remaining -= used
            if tls is not None:
                return tls
        else:
            tls, used = await self._try_tls(
                address,
                port,
                hostname,
                remaining,
                evidence,
                probes,
                errors,
            )
            remaining -= used
            if tls is not None:
                if tls.service is Service.TLS and remaining > 0:
                    https, http_used = await self._try_http(
                        address=address,
                        port=port,
                        hostname=hostname,
                        use_tls=True,
                        remaining=remaining,
                        prior_evidence=tls.evidence,
                        prior_metadata=tls.metadata,
                        probes=probes,
                        errors=errors,
                    )
                    remaining -= http_used
                    if https is not None:
                        return https
                return tls
            http, used = await self._try_http(
                address=address,
                port=port,
                hostname=hostname,
                use_tls=False,
                remaining=remaining,
                prior_evidence=tuple(evidence),
                prior_metadata=None,
                probes=probes,
                errors=errors,
            )
            remaining -= used
            if http is not None:
                return http

        return _unknown_fingerprint(
            evidence=tuple(evidence),
            probes=tuple(probes),
            error=errors[-1] if errors else None,
        )

    async def _try_tls(
        self,
        address: str,
        port: int,
        hostname: str | None,
        remaining: int,
        evidence: list[FingerprintEvidence],
        probes: list[str],
        errors: list[str],
    ) -> tuple[ServiceFingerprint | None, int]:
        if remaining <= 0:
            return None, 0
        probes.append("TLS handshake")
        result = await self._probe_client.tls(
            address,
            port,
            server_hostname=hostname,
        )
        if not result.succeeded:
            if result.error:
                errors.append(result.error)
            return None, 1
        fingerprint = _tls_fingerprint(result, tuple(evidence))
        return fingerprint, 1

    async def _try_http(
        self,
        *,
        address: str,
        port: int,
        hostname: str | None,
        use_tls: bool,
        remaining: int,
        prior_evidence: tuple[FingerprintEvidence, ...],
        prior_metadata: dict[str, str] | None,
        probes: list[str],
        errors: list[str],
    ) -> tuple[ServiceFingerprint | None, int]:
        used = 0
        host_header = hostname or address
        scheme = "HTTPS" if use_tls else "HTTP"
        for method in ("HEAD", "GET"):
            if used >= remaining:
                break
            label = f"{scheme} {method}"
            probes.append(label)
            response = await self._probe_client.http(
                address,
                port,
                method=method,
                host_header=host_header,
                use_tls=use_tls,
                server_hostname=hostname,
            )
            used += 1
            if response.error:
                errors.append(response.error)
            parsed = parse_http_response(
                response.data,
                probe_used=label,
                encrypted=use_tls,
                prior_evidence=prior_evidence,
                prior_metadata=prior_metadata,
            )
            if parsed is not None:
                return parsed, used
        return None, used


def _tls_fingerprint(
    result: TLSProbeResult,
    prior_evidence: tuple[FingerprintEvidence, ...],
) -> ServiceFingerprint:
    metadata: dict[str, str] = {}
    if result.version:
        metadata["tls_version"] = result.version
    if result.cipher:
        metadata["cipher"] = result.cipher
    if result.certificate:
        metadata.update(
            {f"certificate_{key}": value for key, value in result.certificate.items()}
        )
    details = [value for value in (result.version, result.cipher) if value]
    return ServiceFingerprint(
        service=Service.TLS,
        confidence=Confidence.HIGH,
        evidence=(
            *prior_evidence,
            make_evidence(
                EvidenceSource.TLS_HANDSHAKE,
                "TLS handshake completed successfully"
                + (f" ({', '.join(details)})." if details else "."),
            ),
        ),
        probe_used="TLS handshake",
        encrypted=True,
        metadata=metadata,
    )


def _unknown_fingerprint(
    *,
    evidence: tuple[FingerprintEvidence, ...],
    probes: tuple[str, ...],
    error: str | None,
) -> ServiceFingerprint:
    if not evidence:
        evidence = (
            make_evidence(
                EvidenceSource.OBSERVATION,
                "No recognizable bounded application-layer response was obtained.",
            ),
        )
    return ServiceFingerprint(
        service=Service.UNKNOWN,
        confidence=Confidence.LOW,
        evidence=evidence,
        probe_used=", ".join(probes)[:100],
        error=error,
    )


def _safe_error(exc: BaseException) -> str:
    message = " ".join(str(exc).split())[:200]
    return f"{exc.__class__.__name__}: {message}" if message else exc.__class__.__name__
