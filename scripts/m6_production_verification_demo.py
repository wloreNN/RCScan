"""Exercise the production nginx identity rule against the localhost M4 server."""

from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime

from rcscan.findings.models import (
    EvidenceType,
    Finding,
    FindingEvidence,
    FindingType,
    Priority,
    RemediationGuidance,
    RemediationProvenance,
    Severity,
)
from rcscan.findings.policy import stable_finding_id
from rcscan.fingerprint.models import Confidence, Service
from rcscan.verification.engine import VerificationEngine
from rcscan.verification.models import VerificationStatus
from rcscan.verification.registry import production_registry
from rcscan.vuln.models import Applicability, LookupProvenance

HOST = "127.0.0.1"
DEFAULT_PORT = 8080
VERSION = "1.24.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the production nginx identity rule against the local M4 server."
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    if not 1 <= args.port <= 65_535:
        parser.error("--port must be between 1 and 65535.")
    return args


def demo_finding(port: int) -> Finding:
    return Finding(
        finding_id=stable_finding_id(
            host=HOST,
            port=port,
            service=Service.HTTP,
            vendor="nginx",
            product="nginx",
            cve_id="CVE-DEMO-M6-NGINX-IDENTITY",
        ),
        title="Synthetic finding used to exercise production identity verification",
        type=FindingType.KNOWN_VULNERABILITY,
        host=HOST,
        port=port,
        service=Service.HTTP,
        product="nginx",
        version=VERSION,
        cve_id="CVE-DEMO-M6-NGINX-IDENTITY",
        description=(
            "Synthetic local acceptance finding; the CVE identifier is not real."
        ),
        evidence=(
            FindingEvidence(
                type=EvidenceType.OBSERVED,
                summary=f"Synthetic prior fingerprint recorded nginx {VERSION}.",
            ),
        ),
        applicability=Applicability.INDETERMINATE,
        confidence=Confidence.MEDIUM,
        confidence_reason="Synthetic evidence used only for local acceptance.",
        severity=Severity.UNKNOWN,
        priority=Priority.INFORMATIONAL,
        remediation=RemediationGuidance(
            text="No remediation is required for this synthetic acceptance check.",
            provenance=RemediationProvenance.GENERIC,
            source="RCScan synthetic demo",
        ),
        source="rcscan-synthetic-demo",
        provider_provenance=LookupProvenance.SYNTHETIC,
        first_observed=datetime.now(UTC),
    )


async def run(port: int) -> int:
    engine = VerificationEngine(
        timeout_seconds=2.0,
        max_response_bytes=16_384,
        max_requests_per_finding=2,
        max_total_requests=20,
        concurrency=2,
        registry=production_registry(),
    )
    result = (await engine.verify((demo_finding(port),)))[0]
    print("RCScan M6B PRODUCTION-RULE LOCAL ACCEPTANCE")
    print("The finding and CVE are synthetic. No exploitation is performed.")
    print(f"Verification ID: {result.verification_id}")
    print(f"Status: {result.status.value}")
    print(f"Verifier: {result.verifier_name}")
    print(f"Rule: {result.rule_id}")
    print(f"Requests: {result.requests_attempted}")
    print(f"Reason: {result.reason}")
    for evidence in result.evidence:
        print(f"Evidence: {evidence.summary}")
    return 0 if result.status is VerificationStatus.VERIFIED else 1


def main() -> None:
    args = parse_args()
    raise SystemExit(asyncio.run(run(args.port)))


if __name__ == "__main__":
    main()
