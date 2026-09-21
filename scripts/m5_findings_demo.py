"""Offline synthetic demonstration of M5 findings and priority policy."""

from datetime import UTC, datetime

from rcscan.findings.models import (
    EvidenceType,
    Finding,
    FindingEvidence,
    FindingType,
)
from rcscan.findings.policy import (
    priority_for,
    remediation_for,
    severity_from_cvss,
    stable_finding_id,
)
from rcscan.fingerprint.models import Confidence, Service
from rcscan.vuln.models import (
    Applicability,
    CandidateStatus,
    CVSSMetric,
    LookupProvenance,
    VulnerabilityCandidate,
)

OBSERVED_AT = datetime(2026, 1, 1, tzinfo=UTC)
CVSS = CVSSMetric(
    version="3.1",
    base_score=9.8,
    base_severity="CRITICAL",
    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
)


def candidate(
    cve_id: str,
    applicability: Applicability,
    confidence: Confidence,
) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        cve_id=cve_id,
        source="rcscan-synthetic-demo",
        status=CandidateStatus.POTENTIAL_MATCH,
        description="Synthetic demonstration record; this is not a real CVE.",
        cvss=CVSS,
        affected_match=applicability,
        environment_applicability=applicability,
        match_confidence=confidence,
        match_reason=(
            "Observed version matches the synthetic affected range."
            if applicability is Applicability.MATCH
            else "Additional synthetic environment conditions are unresolved."
        ),
        fingerprint_evidence_reference="DemoServer 1.2.0 synthetic evidence",
        lookup_at=OBSERVED_AT,
        provenance=LookupProvenance.SYNTHETIC,
    )


def finding(item: VulnerabilityCandidate) -> Finding:
    severity = severity_from_cvss(item.cvss)
    return Finding(
        finding_id=stable_finding_id(
            host="127.0.0.1",
            port=8080,
            service=Service.HTTP,
            vendor="rcscan_demo",
            product="demoserver",
            cve_id=item.cve_id,
        ),
        title=f"Potential known vulnerability: {item.cve_id}",
        type=FindingType.KNOWN_VULNERABILITY,
        host="127.0.0.1",
        port=8080,
        service=Service.HTTP,
        product="DemoServer",
        version="1.2.0",
        cve_id=item.cve_id,
        description=item.description,
        evidence=(
            FindingEvidence(
                type=EvidenceType.OBSERVED,
                summary="Observed DemoServer 1.2.0 in synthetic bounded evidence.",
            ),
            FindingEvidence(
                type=EvidenceType.NORMALIZED,
                summary=(
                    "Synthetic identity: vendor=rcscan_demo, "
                    "product=demoserver, version=1.2.0."
                ),
            ),
            FindingEvidence(
                type=EvidenceType.CORRELATION,
                summary=item.match_reason,
            ),
        ),
        applicability=item.environment_applicability,
        confidence=item.match_confidence,
        confidence_reason=(
            "Synthetic confidence chosen to demonstrate the documented M5 policy."
        ),
        cvss=item.cvss,
        severity=severity,
        priority=priority_for(
            severity,
            item.environment_applicability,
            item.match_confidence,
        ),
        remediation=remediation_for(item),
        source=item.source,
        provider_provenance=item.provenance,
        first_observed=OBSERVED_AT,
    )


def main() -> None:
    examples = (
        finding(candidate("CVE-DEMO-0001", Applicability.MATCH, Confidence.HIGH)),
        finding(
            candidate(
                "CVE-DEMO-0002",
                Applicability.INDETERMINATE,
                Confidence.MEDIUM,
            )
        ),
    )
    print("RCScan M5 SYNTHETIC OFFLINE DEMO")
    print("No target or provider was contacted. All CVE-DEMO identifiers are not real.")
    print("Observed: DemoServer 1.2.0")
    for item in examples:
        print(f"\nStatus: POTENTIAL known vulnerability ({item.cve_id})")
        print(f"Published CVSS: {item.cvss.base_score:.1f} {item.severity.value}")
        print(f"Applicability: {item.applicability.value}")
        print(f"Confidence: {item.confidence.value}")
        print(f"Priority: {item.priority.value}")
        print(
            f"Remediation provenance: {item.remediation.provenance.value} "
            f"({item.remediation.source})"
        )


if __name__ == "__main__":
    main()
