"""Deduplicated, conservative vulnerability candidate correlation."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from rcscan.fingerprint.models import Confidence
from rcscan.network.models import HostScanResult, PortResult, PortState
from rcscan.vuln.cache import VulnerabilityCache
from rcscan.vuln.errors import VulnerabilityIntelligenceError
from rcscan.vuln.models import (
    Applicability,
    CandidateStatus,
    CVSSMetric,
    NormalizedIdentity,
    ProviderQueryResult,
    VulnerabilityCandidate,
    VulnerabilityRecord,
)
from rcscan.vuln.normalization import normalize_fingerprint
from rcscan.vuln.providers.base import VulnerabilityProvider
from rcscan.vuln.versioning import match_affected_range


@dataclass(frozen=True, slots=True)
class _Correlation:
    candidates: tuple[VulnerabilityCandidate, ...] = ()
    error: str | None = None


class VulnerabilityEngine:
    """Query normalized identities once and attach candidate metadata."""

    def __init__(
        self,
        provider: VulnerabilityProvider,
        *,
        cache: VulnerabilityCache | None,
        max_provider_requests: int,
        max_candidates_per_identity: int,
    ) -> None:
        self._provider = provider
        self._cache = cache
        self._max_provider_requests = max_provider_requests
        self._max_candidates = max_candidates_per_identity
        self._logger = logging.getLogger(__name__)

    async def enrich_hosts(
        self,
        hosts: tuple[HostScanResult, ...],
    ) -> tuple[HostScanResult, ...]:
        identities: dict[str, NormalizedIdentity] = {}
        port_identities: dict[tuple[int, int], str] = {}
        for host_index, host in enumerate(hosts):
            for port_index, port in enumerate(host.ports):
                identity = _identity_for_port(port)
                if identity is None:
                    continue
                identities.setdefault(identity.cache_key, identity)
                port_identities[(host_index, port_index)] = identity.cache_key

        correlations: dict[str, _Correlation] = {}
        requests = 0
        for key, identity in identities.items():
            try:
                result = self._cache.get(self._provider.name, key) if self._cache else None
                if result is None:
                    if requests >= self._max_provider_requests:
                        correlations[key] = _Correlation(
                            error="Provider request limit reached for this scan."
                        )
                        continue
                    requests += 1
                    result = await self._provider.search_product(identity)
                    if result.provider != self._provider.name or result.identity_key != key:
                        raise ValueError("Provider returned mismatched identity metadata.")
                    if self._cache:
                        self._cache.set(result)
                correlations[key] = _Correlation(
                    candidates=correlate_identity(
                        identity,
                        result,
                        self._max_candidates,
                    )
                )
            except asyncio.CancelledError:
                raise
            except VulnerabilityIntelligenceError as exc:
                correlations[key] = _Correlation(error=str(exc)[:300])
            except Exception:
                correlations[key] = _Correlation(
                    error="Vulnerability provider returned an unexpected error."
                )
            self._logger.debug(
                "Vulnerability correlation provider=%s identity=%s candidates=%d available=%s",
                self._provider.name,
                key,
                len(correlations[key].candidates),
                correlations[key].error is None,
            )

        enriched_hosts: list[HostScanResult] = []
        for host_index, host in enumerate(hosts):
            enriched_ports: list[PortResult] = []
            for port_index, port in enumerate(host.ports):
                identity_key = port_identities.get((host_index, port_index))
                if identity_key is None:
                    enriched_ports.append(port)
                    continue
                correlation = correlations[identity_key]
                enriched_ports.append(
                    port.model_copy(
                        update={
                            "vulnerability_candidates": correlation.candidates,
                            "vulnerability_lookup_error": correlation.error,
                        }
                    )
                )
            enriched_hosts.append(host.model_copy(update={"ports": tuple(enriched_ports)}))
        return tuple(enriched_hosts)


def _identity_for_port(port: PortResult) -> NormalizedIdentity | None:
    if port.state is not PortState.OPEN or port.fingerprint is None:
        return None
    return normalize_fingerprint(port.fingerprint)


def correlate_identity(
    identity: NormalizedIdentity,
    result: ProviderQueryResult,
    limit: int,
) -> tuple[VulnerabilityCandidate, ...]:
    candidates: list[VulnerabilityCandidate] = []
    seen: set[str] = set()
    for record in result.records:
        if record.cve_id in seen:
            continue
        candidate = _candidate_for_record(identity, record, result)
        if candidate is None:
            continue
        seen.add(record.cve_id)
        candidates.append(candidate)
        if len(candidates) >= limit:
            break
    return tuple(candidates)


def _candidate_for_record(
    identity: NormalizedIdentity,
    record: VulnerabilityRecord,
    result: ProviderQueryResult,
) -> VulnerabilityCandidate | None:
    matching_ranges = tuple(
        affected
        for affected in record.affected
        if affected.vendor == identity.vendor and affected.product == identity.product
    )
    if not matching_ranges:
        return None
    outcomes = tuple(match_affected_range(identity, affected) for affected in matching_ranges)
    if Applicability.MATCH in outcomes:
        applicability = Applicability.MATCH
        applicable_ranges = tuple(
            affected
            for affected, outcome in zip(matching_ranges, outcomes, strict=True)
            if outcome is Applicability.MATCH
        )
        conditions_unknown = any(item.conditions_unverified for item in applicable_ranges)
        environment = (
            Applicability.INDETERMINATE if conditions_unknown else Applicability.MATCH
        )
        confidence = (
            Confidence.HIGH
            if identity.confidence is Confidence.HIGH and not conditions_unknown
            else Confidence.MEDIUM
        )
        reason = "Observed version matches a published affected version range."
        if conditions_unknown:
            reason += " Additional environment conditions were not verified."
    elif Applicability.INDETERMINATE in outcomes:
        applicability = Applicability.INDETERMINATE
        environment = Applicability.INDETERMINATE
        confidence = Confidence.LOW
        reason = "Product matched, but the published version range was not safely comparable."
    else:
        return None

    return VulnerabilityCandidate(
        cve_id=record.cve_id,
        source=record.source,
        status=CandidateStatus.POTENTIAL_MATCH,
        published=record.published,
        last_modified=record.last_modified,
        description=record.description,
        cvss=_preferred_cvss(record),
        references=record.references,
        affected_match=applicability,
        environment_applicability=environment,
        match_confidence=confidence,
        match_reason=reason,
        fingerprint_evidence_reference=(
            f"{identity.original_product} {identity.version} "
            f"({identity.reason})"
        )[:500],
        lookup_at=result.lookup_at,
        provenance=result.provenance,
        metadata=record.metadata,
    )


def _preferred_cvss(record: VulnerabilityRecord) -> CVSSMetric | None:
    if not record.cvss:
        return None
    return max(record.cvss, key=lambda metric: _cvss_version_key(metric.version))


def _cvss_version_key(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError:
        return ()
