"""Optional explicit live NVD query using product/version only."""

from __future__ import annotations

import argparse
import asyncio

from rcscan.core.config import load_config
from rcscan.fingerprint.models import Confidence, Service, ServiceFingerprint
from rcscan.vuln.errors import VulnerabilityIntelligenceError
from rcscan.vuln.normalization import normalize_fingerprint
from rcscan.vuln.providers.nvd import NVDProvider


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "OPTIONAL live NVD query. Sends only a normalized product CPE/version; "
            "never target addresses, hostnames, banners, or scan IDs."
        )
    )
    parser.add_argument("product", help="Supported exact product, for example nginx.")
    parser.add_argument("version", help="Dotted numeric observed version.")
    return parser.parse_args()


async def query(product: str, version: str) -> int:
    fingerprint = ServiceFingerprint(
        service=Service.UNKNOWN,
        product=product,
        version=version,
        confidence=Confidence.HIGH,
        evidence=(),
        probe_used="manual live-query helper input",
    )
    identity = normalize_fingerprint(fingerprint)
    if identity is None:
        print("Product/version did not resolve through the conservative mapping.")
        return 2

    settings = load_config().vulnerability
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
    print("OPTIONAL LIVE NVD REQUEST")
    print(f"Sending only: {identity.cpe23}")
    try:
        result = await provider.search_product(identity)
    except VulnerabilityIntelligenceError as exc:
        print(f"NVD unavailable: {exc}")
        return 1
    print(f"NVD request succeeded; records returned: {len(result.records)}")
    for record in result.records[:10]:
        print(record.cve_id)
    if len(result.records) > 10:
        print(f"... {len(result.records) - 10} additional records not displayed")
    return 0


def main() -> None:
    args = parse_args()
    raise SystemExit(asyncio.run(query(args.product, args.version)))


if __name__ == "__main__":
    main()
