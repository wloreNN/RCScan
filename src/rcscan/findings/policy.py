"""Transparent severity, priority, remediation, and identity policies."""

from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

from rcscan.findings.models import (
    Priority,
    RemediationGuidance,
    RemediationProvenance,
    Severity,
)
from rcscan.fingerprint.models import Confidence, Service
from rcscan.vuln.models import Applicability, CVSSMetric, VulnerabilityCandidate

_PRIORITY_LEVELS = (
    Priority.INFORMATIONAL,
    Priority.LOW,
    Priority.MEDIUM,
    Priority.HIGH,
    Priority.CRITICAL,
)
_SEVERITY_LEVEL = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_GENERIC_REMEDIATION = (
    "Apply the vendor security update or migrate to a supported release that the "
    "vendor identifies as not affected. Confirm deployment-specific applicability "
    "against the vendor advisory. Until remediation is complete, restrict unnecessary "
    "network exposure as a compensating control."
)


def severity_from_cvss(metric: CVSSMetric | None) -> Severity:
    """Normalize severity from the published base score without inventing a score."""
    if metric is None:
        return Severity.UNKNOWN
    score = metric.base_score
    if score == 0:
        return Severity.INFORMATIONAL
    if score < 4:
        return Severity.LOW
    if score < 7:
        return Severity.MEDIUM
    if score < 9:
        return Severity.HIGH
    return Severity.CRITICAL


def priority_for(
    severity: Severity,
    applicability: Applicability,
    confidence: Confidence,
) -> Priority:
    """Apply the documented deterministic priority decision table."""
    if applicability is Applicability.NO_MATCH:
        return Priority.INFORMATIONAL
    level = _SEVERITY_LEVEL.get(severity)
    if level is None:
        return Priority.INFORMATIONAL
    if confidence is Confidence.LOW:
        reduction = 2
    elif applicability is Applicability.INDETERMINATE or confidence is Confidence.MEDIUM:
        reduction = 1
    else:
        reduction = 0
    return _PRIORITY_LEVELS[max(0, level - reduction)]


def remediation_for(candidate: VulnerabilityCandidate) -> RemediationGuidance:
    """Prefer explicitly sourced provider guidance; otherwise label generic advice."""
    text = candidate.metadata.get("remediation")
    source = candidate.metadata.get("remediation_source")
    if isinstance(text, str) and text.strip() and isinstance(source, str) and source.strip():
        return RemediationGuidance(
            text=" ".join(text.split())[:1_500],
            provenance=RemediationProvenance.PROVIDER,
            source=" ".join(source.split())[:200],
        )
    return RemediationGuidance(
        text=_GENERIC_REMEDIATION,
        provenance=RemediationProvenance.GENERIC,
        source="RCScan generic guidance",
    )


def bounded_references(
    references: tuple[str, ...],
    *,
    limit: int = 10,
) -> tuple[str, ...]:
    """Keep unique bounded HTTP(S) references in provider order."""
    unique: list[str] = []
    seen: set[str] = set()
    for value in references:
        if not isinstance(value, str):
            continue
        reference = value.strip()[:500]
        parsed = urlsplit(reference)
        if (
            not reference
            or parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or reference in seen
        ):
            continue
        seen.add(reference)
        unique.append(reference)
        if len(unique) >= limit:
            break
    return tuple(unique)


def stable_finding_id(
    *,
    host: str,
    port: int,
    service: Service,
    vendor: str,
    product: str,
    cve_id: str,
) -> str:
    """Hash normalized non-secret logical identity into a stable finding ID."""
    identity = "\x1f".join(
        (
            host.strip().casefold(),
            str(port),
            "tcp",
            service.value.casefold(),
            vendor.strip().casefold(),
            product.strip().casefold(),
            cve_id.strip().upper(),
        )
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    return f"AF-{digest}"
