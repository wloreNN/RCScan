"""Deterministic conversion of M4 candidates into explainable findings."""

from __future__ import annotations

import logging
from typing import Any

from rcscan.findings.models import (
    EvidenceType,
    Finding,
    FindingEvidence,
    FindingType,
)
from rcscan.findings.policy import (
    bounded_references,
    priority_for,
    remediation_for,
    severity_from_cvss,
    stable_finding_id,
)
from rcscan.fingerprint.models import Confidence, Service
from rcscan.network.models import HostScanResult, PortResult, PortState
from rcscan.vuln.models import Applicability, VulnerabilityCandidate
from rcscan.vuln.normalization import normalize_fingerprint


class FindingEngine:
    """Generate findings using existing in-memory evidence only."""

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

    def generate(self, hosts: tuple[HostScanResult, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for host in hosts:
            for port in host.ports:
                for index, candidate in enumerate(port.vulnerability_candidates):
                    try:
                        finding = self._from_candidate(port, candidate)
                    except Exception:
                        self._logger.debug(
                            "Skipped malformed finding candidate host=%s port=%d index=%d",
                            port.host,
                            port.port,
                            index,
                            exc_info=True,
                        )
                        continue
                    if finding is None or finding.finding_id in seen:
                        continue
                    seen.add(finding.finding_id)
                    findings.append(finding)
        return tuple(findings)

    def _from_candidate(
        self,
        port: PortResult,
        candidate: object,
    ) -> Finding | None:
        if (
            port.state is not PortState.OPEN
            or port.fingerprint is None
            or port.fingerprint.service is Service.UNKNOWN
            or not isinstance(candidate, VulnerabilityCandidate)
        ):
            return None
        identity = normalize_fingerprint(port.fingerprint)
        if identity is None:
            return None
        applicability = _effective_applicability(candidate)
        if applicability is None or applicability is Applicability.NO_MATCH:
            return None

        severity = severity_from_cvss(candidate.cvss)
        evidence = _evidence_for(port, candidate, identity.vendor, identity.product)
        return Finding(
            finding_id=stable_finding_id(
                host=port.host,
                port=port.port,
                service=port.fingerprint.service,
                vendor=identity.vendor,
                product=identity.product,
                cve_id=candidate.cve_id,
            ),
            title=f"Potential known vulnerability: {candidate.cve_id}",
            type=FindingType.KNOWN_VULNERABILITY,
            host=port.host,
            port=port.port,
            service=port.fingerprint.service,
            product=port.fingerprint.product,
            version=port.fingerprint.version,
            cve_id=candidate.cve_id,
            description=candidate.description,
            evidence=evidence,
            applicability=applicability,
            confidence=candidate.match_confidence,
            confidence_reason=_confidence_reason(candidate, applicability),
            cvss=candidate.cvss,
            severity=severity,
            priority=priority_for(
                severity,
                applicability,
                candidate.match_confidence,
            ),
            remediation=remediation_for(candidate),
            references=bounded_references(candidate.references),
            source=candidate.source,
            provider_provenance=candidate.provenance,
            first_observed=port.timestamp,
            metadata=_bounded_metadata(candidate.metadata),
        )


def _effective_applicability(
    candidate: VulnerabilityCandidate,
) -> Applicability | None:
    values = (candidate.affected_match, candidate.environment_applicability)
    if Applicability.NO_MATCH in values:
        return Applicability.NO_MATCH
    if Applicability.INDETERMINATE in values:
        return Applicability.INDETERMINATE
    if values == (Applicability.MATCH, Applicability.MATCH):
        return Applicability.MATCH
    return None


def _evidence_for(
    port: PortResult,
    candidate: VulnerabilityCandidate,
    vendor: str,
    product: str,
) -> tuple[FindingEvidence, ...]:
    fingerprint = port.fingerprint
    if fingerprint is None:
        return ()
    observed_product = fingerprint.product or "unknown product"
    observed_version = fingerprint.version or "unknown version"
    evidence = [
        FindingEvidence(
            type=EvidenceType.OBSERVED,
            summary=(
                f"Observed {fingerprint.service.value} service identifying as "
                f"{observed_product} {observed_version}."
            ),
        )
    ]
    evidence.extend(
        FindingEvidence(type=EvidenceType.OBSERVED, summary=item.summary)
        for item in fingerprint.evidence[:5]
    )
    evidence.extend(
        (
            FindingEvidence(
                type=EvidenceType.NORMALIZED,
                summary=(
                    f"Normalized identity: vendor={vendor}, product={product}, "
                    f"version={observed_version}."
                ),
            ),
            FindingEvidence(
                type=EvidenceType.CORRELATION,
                summary=candidate.match_reason,
            ),
        )
    )
    return tuple(evidence)


def _confidence_reason(
    candidate: VulnerabilityCandidate,
    applicability: Applicability,
) -> str:
    if candidate.match_confidence is Confidence.HIGH:
        return (
            "HIGH because trusted product and explicit version evidence matched a "
            "published affected range with no unresolved environment conditions."
        )
    if candidate.match_confidence is Confidence.MEDIUM:
        if applicability is Applicability.INDETERMINATE:
            return (
                "MEDIUM because the product/version range matched, but additional "
                "deployment or environment conditions remain unresolved."
            )
        return (
            "MEDIUM because the product/version correlation is useful but its evidence "
            "does not support high confidence."
        )
    return (
        "LOW because the product candidate is defensible, but the published affected "
        "version information could not be compared reliably."
    )


def _bounded_metadata(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            continue
        normalized_key = key.casefold().replace("-", "_")
        if normalized_key in {"api_key", "apikey", "authorization", "token", "secret"}:
            continue
        result[key[:100]] = item[:500]
        if len(result) >= 20:
            break
    return result
