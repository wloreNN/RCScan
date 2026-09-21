"""Small explicit product-to-CPE normalization layer."""

from __future__ import annotations

import re

from rcscan.fingerprint.models import ServiceFingerprint
from rcscan.vuln.models import NormalizedIdentity
from rcscan.vuln.versioning import parse_version

_WHITESPACE = re.compile(r"\s+")
_PRODUCT_MAPPINGS: dict[str, tuple[str, str]] = {
    "nginx": ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "apache": ("apache", "http_server"),
    "apache http server": ("apache", "http_server"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
}


def normalize_fingerprint(
    fingerprint: ServiceFingerprint,
) -> NormalizedIdentity | None:
    """Resolve only explicit supported aliases with a dotted numeric version."""
    if fingerprint.product is None or fingerprint.version is None:
        return None
    normalized_product = _WHITESPACE.sub(" ", fingerprint.product.strip()).casefold()
    mapping = _PRODUCT_MAPPINGS.get(normalized_product)
    if mapping is None or parse_version(fingerprint.version) is None:
        return None
    vendor, product = mapping
    version = fingerprint.version
    return NormalizedIdentity(
        original_product=fingerprint.product,
        vendor=vendor,
        product=product,
        version=version,
        cpe23=_build_cpe(vendor, product, version),
        confidence=fingerprint.confidence,
        reason=(
            "Explicit product and dotted numeric version were observed in "
            "bounded service fingerprint evidence."
        ),
    )


def _build_cpe(vendor: str, product: str, version: str) -> str:
    fields = ("a", vendor, product, version, "*", "*", "*", "*", "*", "*", "*")
    return "cpe:2.3:" + ":".join(_escape_cpe_field(field) for field in fields)


def _escape_cpe_field(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace(":", "\\:")
        .replace("?", "\\?")
        .replace("*", "\\*")
        if value != "*"
        else value
    )
