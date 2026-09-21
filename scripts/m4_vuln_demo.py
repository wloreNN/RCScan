"""Offline synthetic demonstration of M4 version-range correlation."""

from datetime import UTC, datetime

from rcscan.fingerprint.models import Confidence
from rcscan.vuln.engine import correlate_identity
from rcscan.vuln.models import (
    AffectedRange,
    LookupProvenance,
    NormalizedIdentity,
    ProviderQueryResult,
    VulnerabilityRecord,
)


def main() -> None:
    identity = NormalizedIdentity(
        original_product="DemoServer",
        vendor="rcscan_demo",
        product="demoserver",
        version="1.2.0",
        cpe23="cpe:2.3:a:rcscan_demo:demoserver:1.2.0:*:*:*:*:*:*:*",
        confidence=Confidence.HIGH,
        reason="Synthetic explicit product/version evidence.",
    )
    record = VulnerabilityRecord(
        cve_id="CVE-DEMO-0001",
        source="rcscan-synthetic-demo",
        description="Synthetic demonstration record; this is not a real CVE.",
        affected=(
            AffectedRange(
                vendor="rcscan_demo",
                product="demoserver",
                version_start_including="1.0.0",
                version_end_excluding="1.3.0",
            ),
        ),
    )
    lookup = ProviderQueryResult(
        provider="synthetic-demo",
        identity_key=identity.cache_key,
        records=(record,),
        lookup_at=datetime.now(UTC),
        provenance=LookupProvenance.SYNTHETIC,
    )
    candidates = correlate_identity(identity, lookup, limit=10)

    print("RCScan M4 SYNTHETIC OFFLINE DEMO")
    print("No external provider was contacted. CVE-DEMO-0001 is not a real CVE.")
    print(f"Observed: DemoServer {identity.version}")
    print("Synthetic affected range: >=1.0.0 and <1.3.0")
    for candidate in candidates:
        print(f"Candidate: {candidate.cve_id}")
        print(f"Version match: {candidate.affected_match.value}")
        print(f"Status: {candidate.status.value}")
        print(f"Match confidence: {candidate.match_confidence.value}")
        print(f"Reason: {candidate.match_reason}")


if __name__ == "__main__":
    main()
